package gg.lode.sign;

import gg.lode.sign.api.bootstrap.SignBootstrap;
import gg.lode.sign.loader.CloudBlobLoader;
import gg.lode.sign.loader.CloudBlobLoader.LoaderUpdate;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public final class SignLoader extends JavaPlugin {

    private static final String AES_KEY_RESOURCE = "cloud/aes.key";
    private static final String ED25519_PUB_RESOURCE = "cloud/ed25519-public.key";
    private static final String LOADER_TOKEN_RESOURCE = "cloud/loader-token.key";
    private static final String BOOTSTRAP_CLASS = "gg.lode.sign.Sign";
    private static final String LOADER_CONFIG_FILE = "loader.yml";

    private static final byte[] MAGIC = "SGBLOB\0\0".getBytes(StandardCharsets.UTF_8);
    private static final int FORMAT_VERSION = 1;
    private static final int NONCE_LEN = 12;

    private SignBootstrap bootstrap;
    private URLClassLoader implLoader;
    private Path runtimeJar;
    private String loadFailureReason;

    // Captured during loadBootstrap so onEnable can run a background self-update.
    private CloudBlobLoader cloudLoader;
    private byte[] edPubKey;
    private boolean autoUpdateLoader;

    @Override
    public void onLoad() {
        try {
            bootstrap = loadBootstrap();
            bootstrap.onLoad(this);
        } catch (InvalidBlobException ibe) {
            loadFailureReason = "Impl blob is invalid (" + ibe.getMessage() + "). Refusing to load.";
            getLogger().severe(loadFailureReason);
        } catch (CloudBlobLoader.NoBlobException noBlob) {
            loadFailureReason = "No Sign build is available for this server (" + noBlob.getMessage() + ").";
            reportNoBlob(noBlob);
        } catch (CloudBlobLoader.CloudUnavailableException down) {
            loadFailureReason = "Could not reach lode.gg (" + down.getMessage() + ").";
            reportCloudUnavailable(down);
        } catch (Throwable t) {
            loadFailureReason = "Failed to load Sign implementation: " + t.getMessage();
            getLogger().severe(loadFailureReason);
            t.printStackTrace();
        }
    }

    @Override
    public void onEnable() {
        if (bootstrap == null) {
            getLogger().severe(loadFailureReason != null
                    ? loadFailureReason + " Plugin will not enable."
                    : "Sign implementation was never loaded; disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        try {
            bootstrap.onEnable(this);
        } catch (Throwable t) {
            getLogger().severe("Failed to enable Sign implementation: " + t.getMessage());
            t.printStackTrace();
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        // Best-effort loader self-update on a background thread — never blocks
        // enable, never disables the plugin on failure. Staged jars apply on
        // the next server restart via Paper's plugins/update/ folder.
        if (autoUpdateLoader && cloudLoader != null) {
            Thread t = new Thread(this::runSelfUpdate, "Sign-Loader-Update");
            t.setDaemon(true);
            t.start();
        }
    }

    @Override
    public void onDisable() {
        if (bootstrap != null) {
            try { bootstrap.onDisable(this); } catch (Throwable t) { t.printStackTrace(); }
            bootstrap = null;
        }
        if (implLoader != null) {
            try { implLoader.close(); } catch (IOException ignored) {}
            implLoader = null;
        }
        if (runtimeJar != null) {
            try { Files.deleteIfExists(runtimeJar); } catch (IOException ignored) {}
            runtimeJar = null;
        }
    }

    /**
     * lode.gg answered but has no build matching this server — a settled
     * answer, so point the operator at the causes they can actually change.
     */
    private void reportNoBlob(CloudBlobLoader.NoBlobException noBlob) {
        getLogger().severe("=============================================");
        getLogger().severe("Sign could not find a build for this server.");
        getLogger().severe("");
        getLogger().severe("lode.gg said: " + noBlob.getMessage());
        getLogger().severe("This server asked for: " + noBlob.request());
        getLogger().severe("");
        getLogger().severe("That usually means one of:");
        getLogger().severe("  - No Sign build has been published for your");
        getLogger().severe("    Minecraft version yet, or for your server software.");
        getLogger().severe("  - loader_channels in loader.yml names a channel with");
        getLogger().severe("    nothing published in it (default is 'release').");
        getLogger().severe("  - loader_version in loader.yml pins a version that no");
        getLogger().severe("    longer exists. Set it back to 'auto' to take the latest.");
        getLogger().severe("");
        getLogger().severe("Nothing is wrong with your network — lode.gg replied,");
        getLogger().severe("it simply has no matching build.");
        getLogger().severe("Check https://lode.gg/plugin/sign for supported versions.");
        getLogger().severe("=============================================");
    }

    /**
     * lode.gg could not be reached. Distinct from having no build: this one is
     * very likely temporary, and the operator should not go hunting through
     * their config for a cause that is not there.
     */
    private void reportCloudUnavailable(CloudBlobLoader.CloudUnavailableException down) {
        getLogger().severe("=============================================");
        getLogger().severe("Sign could not download its implementation.");
        getLogger().severe("");
        getLogger().severe("Reason: " + down.getMessage());
        getLogger().severe("");
        getLogger().severe("lode.gg could not be reached or did not answer properly.");
        getLogger().severe("This is usually temporary. It can mean:");
        getLogger().severe("  - lode.gg is down or having problems right now.");
        getLogger().severe("  - This machine has no outbound internet access, or a");
        getLogger().severe("    firewall/proxy is blocking https://lode.gg.");
        getLogger().severe("  - DNS on this machine cannot resolve lode.gg.");
        getLogger().severe("");
        getLogger().severe("No valid cached build was on disk either, so nothing");
        getLogger().severe("could be loaded offline. Restart the server to try again.");
        getLogger().severe("=============================================");
    }

    private SignBootstrap loadBootstrap() throws Exception {
        File dataFolder = getDataFolder();
        if (!dataFolder.exists() && !dataFolder.mkdirs()) {
            throw new IOException("Could not create data folder: " + dataFolder);
        }
        YamlConfiguration loaderCfg = loadLoaderConfig(dataFolder);
        String pinnedVersion = loaderCfg.getString("loader_version", "auto");

        String loaderToken = new String(readResource(LOADER_TOKEN_RESOURCE), StandardCharsets.UTF_8).trim();
        String mcVersion = detectMinecraftVersion();
        String loaderChannels = loaderCfg.getString("loader_channels", "release");
        CloudBlobLoader blobLoader = new CloudBlobLoader(getLogger(), "sign", loaderToken, mcVersion, loaderChannels);
        blobLoader.expectedMagic(MAGIC);
        byte[] blob = blobLoader.resolve(pinnedVersion);
        byte[] aesKey = readResource(AES_KEY_RESOURCE);
        byte[] edPub = readResource(ED25519_PUB_RESOURCE);

        // Stash for the onEnable self-update pass.
        this.cloudLoader = blobLoader;
        this.edPubKey = edPub;
        this.autoUpdateLoader = loaderCfg.getBoolean("auto_update_loader", true);

        byte[] jarBytes = verifyAndDecrypt(blob, aesKey, edPub);

        runtimeJar = Files.createTempFile("sign-runtime", ".jar");
        Files.write(runtimeJar, jarBytes, StandardOpenOption.TRUNCATE_EXISTING);

        URL[] urls = { runtimeJar.toUri().toURL() };
        implLoader = new ChildFirstClassLoader(urls, getClass().getClassLoader());
        Class<?> entry = Class.forName(BOOTSTRAP_CLASS, true, implLoader);
        Object instance = entry.getDeclaredConstructor().newInstance();
        if (!(instance instanceof SignBootstrap)) {
            throw new IllegalStateException(BOOTSTRAP_CLASS + " does not implement SignBootstrap");
        }
        return (SignBootstrap) instance;
    }

    private YamlConfiguration loadLoaderConfig(File dataFolder) throws IOException {
        File cfgFile = new File(dataFolder, LOADER_CONFIG_FILE);
        if (!cfgFile.exists()) {
            try (InputStream in = getResource(LOADER_CONFIG_FILE)) {
                if (in == null) throw new IOException("Missing bundled resource: " + LOADER_CONFIG_FILE);
                Files.copy(in, cfgFile.toPath());
            }
        }
        return YamlConfiguration.loadConfiguration(cfgFile);
    }

    private String detectMinecraftVersion() {
        try {
            String bukkitVersion = getServer().getBukkitVersion();
            int dash = bukkitVersion.indexOf('-');
            String mc = dash > 0 ? bukkitVersion.substring(0, dash) : bukkitVersion;
            if (mc.matches("\\d+\\.\\d+(?:\\.\\d+)?")) return mc;
        } catch (Throwable t) {
            getLogger().warning("Could not detect Minecraft version: " + t.getMessage());
        }
        return null;
    }

    private byte[] readResource(String name) throws IOException {
        try (InputStream in = getResource(name)) {
            if (in == null) throw new IOException("Missing bundled resource: " + name);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    private static byte[] verifyAndDecrypt(byte[] blob, byte[] aesKey, byte[] edPubEncoded) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new InvalidBlobException("bad magic");

        int formatVersion = buf.getInt();
        if (formatVersion != FORMAT_VERSION) throw new InvalidBlobException("unsupported format version " + formatVersion);

        byte[] nonce = new byte[NONCE_LEN];
        buf.get(nonce);
        int ctLen = buf.getInt();
        if (ctLen < 0 || ctLen > buf.remaining()) throw new InvalidBlobException("bad ciphertext length " + ctLen);
        byte[] ciphertext = new byte[ctLen];
        buf.get(ciphertext);
        int sigLen = buf.getInt();
        if (sigLen != 64 || sigLen != buf.remaining()) throw new InvalidBlobException("bad signature length " + sigLen);
        byte[] signature = new byte[sigLen];
        buf.get(signature);

        int signedLen = blob.length - 4 - sigLen;
        byte[] signedSpan = Arrays.copyOfRange(blob, 0, signedLen);
        PublicKey edPub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(edPubEncoded));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(edPub);
        verifier.update(signedSpan);
        if (!verifier.verify(signature)) throw new InvalidBlobException("Ed25519 signature verification failed");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, nonce));
        try {
            return cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException badTag) {
            throw new InvalidBlobException("AES-GCM tag mismatch (wrong key or tampered ciphertext)");
        }
    }

    /**
     * Check lode.gg for a newer loader jar; if one is published and its Ed25519
     * signature verifies against the bundled blob public key, stage it into
     * plugins/update/ with the raw jar. Entirely best-effort: any failure is
     * logged and swallowed.
     */
    private void runSelfUpdate() {
        try {
            LoaderUpdate update = cloudLoader.fetchLoaderUpdate();
            if (update == null || update.version == null) return;

            String current = getPluginMeta().getVersion();
            if (compareVersions(update.version, current) <= 0) return; // not newer
            if (update.signature == null || update.signature.isBlank()) {
                getLogger().info("Loader update " + update.version
                        + " available but unsigned — skipping (manual update required).");
                return;
            }

            byte[] rawJar = cloudLoader.downloadLoaderRaw(update.sha256);
            if (rawJar == null) return;

            if (!verifyEd25519(rawJar, Base64.getDecoder().decode(update.signature), edPubKey)) {
                getLogger().warning("Loader update " + update.version
                        + " signature verification FAILED — refusing to stage it.");
                return;
            }

            Path updateDir = Paths.get("plugins", "update");
            Files.createDirectories(updateDir);
            Path target = updateDir.resolve(currentJarFileName());
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.write(tmp, rawJar);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            getLogger().info("Staged loader update " + update.version
                    + " — it applies on the next server restart.");
        } catch (Throwable t) {
            getLogger().warning("Loader self-update skipped: " + t.getMessage());
        }
    }

    /** File name of this loader jar on disk, for the plugins/update/ target. */
    private String currentJarFileName() {
        try {
            return new File(getClass().getProtectionDomain().getCodeSource().getLocation().toURI()).getName();
        } catch (Exception e) {
            return "Sign-Loader.jar";
        }
    }

    private static boolean verifyEd25519(byte[] data, byte[] signature, byte[] edPubEncoded) {
        try {
            PublicKey edPub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(edPubEncoded));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(edPub);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /** Compare dotted versions numerically; non-numeric tails ignored. Returns
     *  >0 if a newer than b, <0 if older, 0 if equal. */
    static int compareVersions(String a, String b) {
        String[] pa = a.replaceAll("[^0-9.].*$", "").split("\\.");
        String[] pb = b.replaceAll("[^0-9.].*$", "").split("\\.");
        int len = Math.max(pa.length, pb.length);
        for (int i = 0; i < len; i++) {
            int va = i < pa.length ? parseIntSafe(pa[i]) : 0;
            int vb = i < pb.length ? parseIntSafe(pb[i]) : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int parseIntSafe(String s) {
        try { return s.isEmpty() ? 0 : Integer.parseInt(s); }
        catch (NumberFormatException e) { return 0; }
    }

    private static final class InvalidBlobException extends Exception {
        InvalidBlobException(String message) { super(message); }
    }

    // Child-first classloader so the impl jar's bundled classes win over any
    // stale copies shaded into sibling plugins. A small allowlist stays
    // parent-first for shared-contract types — the bootstrap interface and
    // loader-internal helpers must come from the same classloader as the host
    // so instanceof checks succeed.
    private static final class ChildFirstClassLoader extends URLClassLoader {
        private static final List<String> PARENT_FIRST_PREFIXES = List.of(
                "java.", "javax.", "jdk.", "sun.",
                "org.bukkit.", "net.minecraft.", "io.papermc.", "com.destroystokyo.",
                // Platform-shared libs that appear in Paper API signatures.
                "net.kyori.", "io.netty.", "org.slf4j.", "com.mojang.brigadier.",
                // Sign-API is bundled in both the loader jar and the impl jar.
                // Parent-first keeps them as ONE Class<?> so the impl's
                // provider setup and consumers' lookups share one singleton.
                "gg.lode.sign.api.",
                "gg.lode.sign.loader.",
                "gg.lode.sign.SignLoader"
        );

        ChildFirstClassLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    boolean parentFirst = false;
                    for (String prefix : PARENT_FIRST_PREFIXES) {
                        if (name.startsWith(prefix)) { parentFirst = true; break; }
                    }
                    if (parentFirst) {
                        loaded = super.loadClass(name, false);
                    } else {
                        try { loaded = findClass(name); }
                        catch (ClassNotFoundException notInUrl) { loaded = super.loadClass(name, false); }
                    }
                }
                if (resolve) resolveClass(loaded);
                return loaded;
            }
        }
    }
}
