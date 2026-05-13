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
    private final String cacheNameSalt;

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
        this.cacheNameSalt = "blob:v1:" + pluginId
                + ":mc=" + (mcVersion == null ? "any" : mcVersion)
                + ":ch=" + (this.channels == null ? "any" : this.channels) + ":";
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
        Manifest manifest = fetchManifest();
        if (manifest != null) {
            Path cachePath = cachePathFor(manifest.version);
            byte[] cached = readCacheIfMatches(cachePath, manifest.sha256);
            if (cached != null) {
                logger.info("Loaded impl " + manifest.version + " from cache.");
                return cached;
            }
            byte[] bytes = downloadFromManifest(manifest);
            writeCache(cachePath, bytes);
            logger.info("Downloaded impl " + manifest.version + ".");
            return bytes;
        }
        byte[] fallback = readAnyCache();
        if (fallback != null) {
            logger.warning("Cloud manifest unavailable — falling back to last cached impl blob.");
            return fallback;
        }
        throw new IOException("Cloud manifest unavailable and no cached blob on disk.");
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
        HttpRequest req = HttpRequest.newBuilder(manifestUri)
                .timeout(MANIFEST_TIMEOUT)
                .header("Accept", "application/json")
                .header(LOADER_HEADER, loaderToken).GET().build();
        HttpResponse<String> resp;
        try { resp = http.send(req, HttpResponse.BodyHandlers.ofString()); }
        catch (IOException ioe) {
            logger.warning("Cloud manifest fetch threw: " + ioe.getMessage());
            return null;
        }
        if (resp.statusCode() != 200) {
            logger.warning("Cloud manifest returned HTTP " + resp.statusCode());
            return null;
        }
        return parseManifest(resp.body());
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

    private Path cachePathFor(String version) {
        String name = sha256Hex((cacheNameSalt + version).getBytes(StandardCharsets.UTF_8));
        return CACHE_DIR.resolve(name);
    }

    private byte[] readCacheIfMatches(Path path, String expectedSha256Hex) {
        try {
            if (!Files.isRegularFile(path)) return null;
            byte[] bytes = Files.readAllBytes(path);
            if (expectedSha256Hex != null && !sha256Hex(bytes).equalsIgnoreCase(expectedSha256Hex)) return null;
            return bytes;
        } catch (IOException ioe) { return null; }
    }

    private byte[] readAnyCache() {
        if (!Files.isDirectory(CACHE_DIR)) return null;
        try (var stream = Files.list(CACHE_DIR)) {
            return stream.filter(Files::isRegularFile)
                    .max((a, b) -> Long.compare(a.toFile().lastModified(), b.toFile().lastModified()))
                    .map(p -> { try { return Files.readAllBytes(p); } catch (IOException ioe) { return null; } })
                    .orElse(null);
        } catch (IOException ioe) { return null; }
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

    private static final class Manifest {
        String version; String blobUrl; String sha256;
    }
}
