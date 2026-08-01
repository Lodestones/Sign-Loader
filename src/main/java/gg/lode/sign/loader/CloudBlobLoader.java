package gg.lode.sign.loader;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CloudBlobLoader {

    private static final String BASE_URL = "https://lode.gg/api/plugins/";
    private static final Pattern STRING_FIELD = Pattern.compile("\"([A-Za-z0-9_]+)\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PINNED_VERSION = Pattern.compile("^\\d+\\.\\d+\\.\\d+(?:-[\\w.]+)?$");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration MANIFEST_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration BLOB_TIMEOUT = Duration.ofSeconds(30);

    public static final String LOADER_HEADER = "X-Loader-Token";
    private static final Path CACHE_DIR = Paths.get(".cache");

    private final Logger logger;
    private final HttpClient http;
    private final String loaderToken;
    private final String mcVersion;
    private final String channels;
    private final URI manifestUri;
    private final String blobUrlPrefix;
    private final URI loaderUpdateUri;
    private final URI loaderRawUri;
    private final String cacheNameSalt;
    /** Envelope magic prefix used to validate cache-fallback candidates; null skips the check. */
    private byte[] expectedMagic;

    public CloudBlobLoader(Logger logger, String pluginId, String loaderToken, String mcVersion, String channels) {
        this.logger = logger;
        this.http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
        this.loaderToken = loaderToken;
        this.mcVersion = mcVersion;
        this.channels = normalizeChannels(channels);
        StringBuilder query = new StringBuilder();
        if (mcVersion != null) {
            query.append(query.length() == 0 ? "?" : "&");
            query.append("mc=").append(URLEncoder.encode(mcVersion, StandardCharsets.UTF_8));
        }
        if (this.channels != null) {
            query.append(query.length() == 0 ? "?" : "&");
            query.append("channel=").append(URLEncoder.encode(this.channels, StandardCharsets.UTF_8));
        }
        this.manifestUri = URI.create(BASE_URL + pluginId + "/impl/manifest" + query);
        this.blobUrlPrefix = BASE_URL + pluginId + "/impl/";
        this.loaderUpdateUri = URI.create(BASE_URL + pluginId + "/loader/update");
        this.loaderRawUri = URI.create(BASE_URL + pluginId + "/loader/update.jar");
        this.cacheNameSalt = "blob:v1:" + pluginId
                + ":mc=" + (mcVersion == null ? "any" : mcVersion)
                + ":ch=" + (this.channels == null ? "any" : this.channels) + ":";
    }

    /** Set the blob envelope magic so cache-fallback candidates can be validated. */
    public void expectedMagic(byte[] magic) {
        this.expectedMagic = magic;
    }

    private static String normalizeChannels(String raw) {
        if (raw == null) return null;
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) return null;
        return trimmed.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    }

    public byte[] resolve(String pinnedVersion) throws IOException {
        String pinned = normalizePinned(pinnedVersion);
        try {
            if (pinned != null) {
                logger.info("Pinned impl version " + pinned + " (loader_version override).");
                return resolvePinned(pinned);
            }
            return resolveFromManifest();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while fetching impl blob from lode.gg.", ie);
        }
    }

    private static String normalizePinned(String raw) {
        if (raw == null) return null;
        String v = raw.trim();
        if (v.isEmpty() || v.equalsIgnoreCase("auto") || v.equalsIgnoreCase("latest")) return null;
        if (!PINNED_VERSION.matcher(v).matches()) return null;
        return v;
    }

    private byte[] resolveFromManifest() throws IOException, InterruptedException {
        Manifest m;
        try {
            m = fetchManifest();
        } catch (NoBlobException | CloudUnavailableException settledOrDown) {
            // Fall back to the newest valid cached blob so an outage (or a gap
            // in published versions) doesn't take the plugin down with it.
            byte[] fallback = readAnyCache();
            if (fallback != null) {
                logger.warning("Manifest unavailable (" + settledOrDown.getMessage() + ") — using cached blob.");
                return fallback;
            }
            throw settledOrDown;
        }
        Path cp = cachePathFor(m.version);
        byte[] cached = readCacheIfMatches(cp, m.sha256);
        if (cached != null) { logger.info("Loaded impl " + m.version + " from cache."); return cached; }
        byte[] bytes = downloadFromManifest(m);
        writeCache(cp, bytes);
        logger.info("Downloaded impl " + m.version + ".");
        return bytes;
    }

    private byte[] resolvePinned(String version) throws IOException, InterruptedException {
        Path cachePath = cachePathFor(version);
        try {
            byte[] bytes = downloadPinned(version);
            writeCache(cachePath, bytes);
            return bytes;
        } catch (IOException downloadFail) {
            byte[] cached = readCacheIfMatches(cachePath, null);
            if (cached != null) {
                logger.warning("Pinned blob fetch failed — falling back to local cache.");
                return cached;
            }
            throw downloadFail;
        }
    }

    private Manifest fetchManifest() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(manifestUri).timeout(MANIFEST_TIMEOUT)
                .header("Accept", "application/json").header(LOADER_HEADER, loaderToken).GET().build();
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ioe) {
            throw new CloudUnavailableException("could not reach lode.gg (" + ioe.getMessage() + ")", ioe);
        }
        // 404 is lode.gg saying "nothing published matches this server" — a
        // settled answer with its own explanation, not an outage.
        if (resp.statusCode() == 404) {
            String detail = extractField(resp.body(), "error");
            throw new NoBlobException(detail != null ? detail : "no blob matches this server", describeRequest());
        }
        if (resp.statusCode() != 200) {
            throw new CloudUnavailableException("lode.gg returned HTTP " + resp.statusCode() + " for the impl manifest");
        }
        Manifest parsed = parseManifest(resp.body());
        if (parsed == null) throw new CloudUnavailableException("lode.gg returned a malformed impl manifest");
        return parsed;
    }

    private byte[] downloadFromManifest(Manifest manifest) throws IOException, InterruptedException {
        URI url = URI.create(blobUrlPrefix + manifest.version + ".bin");
        HttpRequest req = HttpRequest.newBuilder(url).timeout(BLOB_TIMEOUT)
                .header(LOADER_HEADER, loaderToken).GET().build();
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) throw new IOException("Cloud blob download returned HTTP " + resp.statusCode());
        byte[] bytes = resp.body();
        if (manifest.sha256 != null && !sha256Hex(bytes).equalsIgnoreCase(manifest.sha256)) {
            throw new IOException("Cloud blob checksum mismatch — refusing to load.");
        }
        return bytes;
    }

    private byte[] downloadPinned(String version) throws IOException, InterruptedException {
        URI url = URI.create(blobUrlPrefix + version + ".bin");
        HttpRequest req = HttpRequest.newBuilder(url).timeout(BLOB_TIMEOUT)
                .header(LOADER_HEADER, loaderToken).GET().build();
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) throw new IOException("Pinned blob " + version + " returned HTTP " + resp.statusCode());
        return resp.body();
    }

    private static Manifest parseManifest(String body) {
        Manifest m = new Manifest();
        Matcher matcher = STRING_FIELD.matcher(body);
        while (matcher.find()) {
            switch (matcher.group(1)) {
                case "version" -> m.version = matcher.group(2);
                case "blobUrl" -> m.blobUrl = matcher.group(2);
                case "sha256"  -> m.sha256  = matcher.group(2);
                default -> {}
            }
        }
        return (m.version != null && m.blobUrl != null) ? m : null;
    }

    private static String extractField(String body, String field) {
        if (body == null) return null;
        Matcher matcher = STRING_FIELD.matcher(body);
        while (matcher.find()) {
            if (matcher.group(1).equals(field)) return matcher.group(2);
        }
        return null;
    }

    /** e.g. "Minecraft 26.2, channel alpha" — what we asked lode.gg for. */
    public String describeRequest() {
        return "Minecraft " + (mcVersion == null ? "unknown" : mcVersion)
                + ", channel " + (channels == null ? "release" : channels);
    }

    private Path cachePathFor(String version) {
        String name = sha256Hex((cacheNameSalt + version).getBytes(StandardCharsets.UTF_8));
        return CACHE_DIR.resolve(name);
    }

    private byte[] readCacheIfMatches(Path path, String expectedSha256Hex) {
        try {
            if (!Files.isRegularFile(path)) return null;
            byte[] bytes = Files.readAllBytes(path);
            if (expectedSha256Hex != null && !sha256Hex(bytes).equalsIgnoreCase(expectedSha256Hex)) return null;
            if (expectedSha256Hex == null && !looksLikeBlob(bytes)) return null;
            return bytes;
        } catch (IOException ioe) { return null; }
    }

    /**
     * Newest-first sweep of the cache dir: skip in-flight temp files, validate
     * the envelope magic, and delete anything invalid so one bad file can never
     * poison offline boot again. Returns the newest valid blob, or null.
     */
    private byte[] readAnyCache() {
        if (!Files.isDirectory(CACHE_DIR)) return null;
        List<Path> candidates;
        try (var stream = Files.list(CACHE_DIR)) {
            candidates = stream.filter(Files::isRegularFile)
                    .filter(p -> !p.getFileName().toString().endsWith(".tmp"))
                    .sorted((a, b) -> Long.compare(b.toFile().lastModified(), a.toFile().lastModified()))
                    .toList();
        } catch (IOException ioe) { return null; }
        for (Path candidate : candidates) {
            byte[] bytes;
            try { bytes = Files.readAllBytes(candidate); } catch (IOException ioe) { continue; }
            if (!looksLikeBlob(bytes)) {
                logger.warning("Discarding invalid cache entry " + candidate.getFileName() + " (not a blob).");
                try { Files.deleteIfExists(candidate); } catch (IOException ignored) { }
                continue;
            }
            return bytes;
        }
        return null;
    }

    private boolean looksLikeBlob(byte[] bytes) {
        if (expectedMagic == null) return bytes.length > 0;
        if (bytes.length < expectedMagic.length) return false;
        for (int i = 0; i < expectedMagic.length; i++) {
            if (bytes[i] != expectedMagic[i]) return false;
        }
        return true;
    }

    private void writeCache(Path path, byte[] bytes) {
        try {
            Files.createDirectories(path.getParent());
            Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
            Files.write(tmp, bytes);
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ioe) {
            logger.warning("Failed to write cache " + path + ": " + ioe.getMessage());
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format(Locale.ROOT, "%02x", b));
            return sb.toString();
        } catch (Exception e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }

    /**
     * lode.gg answered, and the answer is that nothing it has published fits
     * this server. Retrying cannot change that.
     */
    public static final class NoBlobException extends IOException {
        private final String request;

        public NoBlobException(String message, String request) {
            super(message);
            this.request = request;
        }

        /** What this server asked for, for the operator-facing report. */
        public String request() { return request; }
    }

    /**
     * lode.gg could not be reached, or answered with a server error. Unlike
     * {@link NoBlobException} this may well succeed on the next try.
     */
    public static final class CloudUnavailableException extends IOException {
        public CloudUnavailableException(String message) { super(message); }
        public CloudUnavailableException(String message, Throwable cause) { super(message, cause); }
    }

    private static final class Manifest {
        String version; String blobUrl; String sha256;
    }

    /**
     * Fetch the published loader auto-update metadata, or null if none is
     * published or the cloud is unreachable (auto-update is best-effort —
     * a failed check never blocks the running loader).
     */
    public LoaderUpdate fetchLoaderUpdate() {
        try {
            HttpRequest req = HttpRequest.newBuilder(loaderUpdateUri)
                    .timeout(MANIFEST_TIMEOUT)
                    .header("Accept", "application/json")
                    .header(LOADER_HEADER, loaderToken).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return null;
            LoaderUpdate u = new LoaderUpdate();
            Matcher matcher = STRING_FIELD.matcher(resp.body());
            while (matcher.find()) {
                switch (matcher.group(1)) {
                    case "version"   -> u.version   = matcher.group(2);
                    case "sha256"    -> u.sha256    = matcher.group(2);
                    case "signature" -> u.signature = matcher.group(2);
                    default -> {}
                }
            }
            return u.version != null ? u : null;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException ioe) {
            return null;
        }
    }

    /**
     * Download the raw (non-injected) loader jar bytes, verifying the SHA-256
     * against the published value. Returns null on any failure.
     */
    public byte[] downloadLoaderRaw(String expectedSha256) {
        try {
            HttpRequest req = HttpRequest.newBuilder(loaderRawUri).timeout(BLOB_TIMEOUT)
                    .header(LOADER_HEADER, loaderToken).GET().build();
            HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) return null;
            byte[] bytes = resp.body();
            if (expectedSha256 != null && !sha256Hex(bytes).equalsIgnoreCase(expectedSha256)) {
                logger.warning("Loader update checksum mismatch — skipping self-update.");
                return null;
            }
            return bytes;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException ioe) {
            return null;
        }
    }

    /** Published loader auto-update metadata. */
    public static final class LoaderUpdate {
        public String version;
        public String sha256;
        public String signature; // base64 Ed25519 over the raw jar bytes; null ⇒ don't update
    }
}
