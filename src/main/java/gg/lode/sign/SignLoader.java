package gg.lode.sign;

import gg.lode.sign.api.bootstrap.SignBootstrap;
import gg.lode.sign.loader.CloudBlobLoader;
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
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class SignLoader extends JavaPlugin {

    private static final String AES_KEY_RESOURCE = "cloud/aes.key";
    private static final String ED25519_PUB_RESOURCE = "cloud/ed25519-public.key";
    private static final String LOADER_TOKEN_RESOURCE = "cloud/loader-token.key";
    private static final String BOOTSTRAP_CLASS = "gg.lode.sign.Sign";

    private static final byte[] MAGIC = "SGBLOB\0\0".getBytes(StandardCharsets.UTF_8);
    private static final int FORMAT_VERSION = 1;
    private static final int NONCE_LEN = 12;

    private SignBootstrap bootstrap;
    private URLClassLoader implLoader;
    private Path runtimeJar;
    private String loadFailureReason;

    @Override
    public void onLoad() {
        try {
            bootstrap = loadBootstrap();
            bootstrap.onLoad(this);
        } catch (InvalidBlobException ibe) {
            loadFailureReason = "Impl blob is invalid (" + ibe.getMessage() + "). Refusing to load.";
            getLogger().severe(loadFailureReason);
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

    private SignBootstrap loadBootstrap() throws Exception {
        File dataFolder = getDataFolder();
        if (!dataFolder.exists() && !dataFolder.mkdirs()) {
            throw new IOException("Could not create data folder: " + dataFolder);
        }
        saveDefaultConfig();
        String pinnedVersion = getConfig().getString("loader_version", "auto");

        String loaderToken = new String(readResource(LOADER_TOKEN_RESOURCE), StandardCharsets.UTF_8).trim();
        String mcVersion = detectMinecraftVersion();
        String loaderChannels = getConfig().getString("loader_channels", "release");
        CloudBlobLoader blobLoader = new CloudBlobLoader(getLogger(), "sign", loaderToken, mcVersion, loaderChannels);
        byte[] blob = blobLoader.resolve(pinnedVersion);
        byte[] aesKey = readResource(AES_KEY_RESOURCE);
        byte[] edPub = readResource(ED25519_PUB_RESOURCE);

        byte[] jarBytes = verifyAndDecrypt(blob, aesKey, edPub);

        runtimeJar = Files.createTempFile("sign-runtime", ".jar");
        Files.write(runtimeJar, jarBytes, StandardOpenOption.TRUNCATE_EXISTING);

        URL[] urls = { runtimeJar.toUri().toURL() };
        implLoader = new URLClassLoader(urls, getClass().getClassLoader());
        Class<?> entry = Class.forName(BOOTSTRAP_CLASS, true, implLoader);
        Object instance = entry.getDeclaredConstructor().newInstance();
        if (!(instance instanceof SignBootstrap)) {
            throw new IllegalStateException(BOOTSTRAP_CLASS + " does not implement SignBootstrap");
        }
        return (SignBootstrap) instance;
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

    private static final class InvalidBlobException extends Exception {
        InvalidBlobException(String message) { super(message); }
    }
}
