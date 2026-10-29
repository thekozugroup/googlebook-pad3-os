package org.googlebook.pad3.updater;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.*;
import javax.net.ssl.HttpsURLConnection;

/** Platform-independent verification and bounded, resumable transport. */
public final class UpdateCore {
    public static final long GIB = 1L << 30;
    public static final int FEED_LIMIT = 512 * 1024;
    public interface Progress { void update(long done, long total) throws IOException; }
    interface Connections { HttpURLConnection open(URL url) throws IOException; }
    static final Connections HTTPS = url -> {
        URLConnection connection = url.openConnection();
        require(connection instanceof HttpsURLConnection, "HTTPS required");
        return (HttpsURLConnection) connection;
    };

    public static void require(boolean condition, String reason) throws IOException {
        if (!condition) throw new IOException(reason);
    }
    public static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) text.append(String.format(Locale.ROOT, "%02x", b & 255));
        return text.toString();
    }
    static MessageDigest digest() throws IOException {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (GeneralSecurityException e) { throw new IOException(e); }
    }
    public static byte[] bounded(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        for (int n; (n = in.read(buffer)) != -1;) {
            require(out.size() <= limit - n, "Response exceeds size limit");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
    public static void hashFormat(String hash) throws IOException {
        require(hash != null && hash.matches("[0-9a-f]{64}"), "Invalid SHA-256");
    }
    public static byte[] verifiedFeed(byte[] publicDer, byte[] bytes, byte[] signature) throws IOException {
        try {
            require(publicDer.length > 0 && publicDer.length <= 4096, "Release verification key is not provisioned");
            require(bytes.length > 0 && bytes.length <= FEED_LIMIT && signature.length > 0 && signature.length <= 1024,
                    "Feed/signature exceeds size limit");
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicDer));
            require(key.getModulus().bitLength() >= 2048, "RSA key is too small");
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update(bytes);
            require(verifier.verify(signature), "Feed signature verification failed");
            return bytes;
        } catch (GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
            throw new IOException("Invalid release key or signature", e);
        }
    }
    public static URL httpsUrl(String text) throws IOException {
        URL url = new URL(text);
        require(url.getProtocol().equals("https") && (url.getPort() == -1 || url.getPort() == 443)
                && url.getUserInfo() == null && url.getRef() == null, "Unsafe update URL");
        return url;
    }
    static boolean redirectHost(String host) {
        return Arrays.asList("github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com").contains(host);
    }
    static HttpURLConnection connect(String text, long start, Connections connections) throws IOException {
        URL url = httpsUrl(text);
        for (int redirects = 0; redirects <= 5; redirects++) {
            require(redirectHost(url.getHost()), "Update redirect host is not allowed");
            HttpURLConnection connection = connections.open(url);
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(20000);
            connection.setRequestProperty("Accept-Encoding", "identity");
            if (start > 0) connection.setRequestProperty("Range", "bytes=" + start + "-");
            int status = connection.getResponseCode();
            if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                String location = connection.getHeaderField("Location");
                connection.disconnect();
                require(location != null, "Redirect has no location");
                url = httpsUrl(new URL(url, location).toString());
            } else return connection;
        }
        throw new IOException("Too many update redirects");
    }
    public static byte[] fetchFeed(String url) throws IOException {
        return fetchBytes(url, FEED_LIMIT);
    }
    public static byte[] fetchSignature(String url) throws IOException {
        return fetchBytes(url + ".sig", 1024);
    }
    static byte[] fetchBytes(String url, int limit) throws IOException {
        HttpURLConnection connection = connect(url, 0, HTTPS);
        try {
            require(connection.getResponseCode() == 200, "Feed HTTP " + connection.getResponseCode());
            require(connection.getContentLengthLong() <= limit, "Feed/signature is too large");
            try (InputStream in = connection.getInputStream()) { return bounded(in, limit); }
        } finally { connection.disconnect(); }
    }
    public static final class Part {
        public final String url, sha256;
        public final long size;
        public Part(String url, long size, String hash) throws IOException {
            URL parsed = httpsUrl(url);
            require(parsed.getHost().equals("github.com") && parsed.getPath().startsWith(
                    "/thekozugroup/googlebook-pad3-os/releases/download/"), "Part must be an owner release asset");
            require(size > 0 && size <= GIB, "Part must be 1 byte..1 GiB");
            hashFormat(hash);
            this.url = url; this.size = size; this.sha256 = hash;
        }
    }
    public static final class Release {
        public String version, baseProfile, otaHash, payloadHash, metadataHash;
        public long sequence, published, expires, otaSize, offset, payloadSize, metadataSize;
        public List<String> fingerprints = new ArrayList<>();
        public List<Part> parts = new ArrayList<>();
        public String[] properties;
        public void validate(long now) throws IOException {
            require(version != null && version.length() <= 120 && !version.isEmpty(), "Invalid release label");
            require(sequence > 0 && published > 0 && published <= now + 300 && expires > now && expires > published,
                    "Expired, premature or invalid release");
            require("erhai-crdroid-20261025".equals(baseProfile), "Native base profile is not supported");
            require(!fingerprints.isEmpty() && fingerprints.size() <= 16, "Missing compatible fingerprints");
            for (String fingerprint : fingerprints) require(fingerprint.length() > 0 && fingerprint.length() <= 1024, "Invalid fingerprint");
            require(otaSize > 0 && otaSize <= 16 * GIB && !parts.isEmpty() && parts.size() <= 32, "Invalid OTA size/parts");
            long sum = 0;
            for (Part part : parts) sum = Math.addExact(sum, part.size);
            require(sum == otaSize, "Part sizes do not equal ZIP size");
            require(offset >= 0 && payloadSize >= 24 && offset <= otaSize - payloadSize,
                    "Payload range is outside ZIP");
            require(metadataSize >= 24 && metadataSize <= 16 * 1024 * 1024 && metadataSize <= payloadSize,
                    "Invalid payload metadata size");
            hashFormat(otaHash); hashFormat(payloadHash); hashFormat(metadataHash);
            Map<String,String> values = properties(properties);
            require(values.get("FILE_SIZE").equals(Long.toString(payloadSize))
                    && values.get("METADATA_SIZE").equals(Long.toString(metadataSize)), "Payload property size mismatch");
            try {
                require(hex(Base64.getDecoder().decode(values.get("FILE_HASH"))).equals(payloadHash)
                        && hex(Base64.getDecoder().decode(values.get("METADATA_HASH"))).equals(metadataHash),
                        "Payload property hash mismatch");
            } catch (IllegalArgumentException e) { throw new IOException("Invalid payload property hash", e); }
        }
    }
    public static Map<String,String> properties(String[] lines) throws IOException {
        require(lines != null && lines.length == 4, "Require exactly four payload properties");
        Map<String,String> result = new TreeMap<>();
        for (String line : lines) {
            int split = line.indexOf('=');
            require(split > 0 && line.length() <= 256 && line.indexOf('\n') < 0 && line.indexOf('\r') < 0, "Invalid payload property");
            require(result.put(line.substring(0, split), line.substring(split + 1)) == null, "Duplicate payload property");
        }
        require(result.keySet().equals(new TreeSet<>(Arrays.asList("FILE_HASH", "FILE_SIZE", "METADATA_HASH", "METADATA_SIZE"))),
                "Unsupported payload property");
        return result;
    }
    public static void guardNative(Release release, Map<String,String> properties, String fingerprint, String[] abis, long pageSize) throws IOException {
        require("1".equals(properties.get("ro.googlebook.pad3.native"))
                && "erhai".equals(properties.get("ro.googlebook.pad3.device"))
                && release.baseProfile.equals(properties.get("ro.googlebook.pad3.base_profile")), "Not the authorized native Pad 3 port/base");
        require(!"1".equals(properties.get("ro.gsid.image_running")), "Native OTA is forbidden inside DSU");
        require("true".equals(properties.get("ro.build.ab_update")) && "true".equals(properties.get("ro.virtual_ab.enabled"))
                && Arrays.asList("_a", "_b").contains(properties.get("ro.boot.slot_suffix")), "Native virtual A/B slot state is missing");
        require(Arrays.asList(abis).contains("arm64-v8a") && pageSize == 4096, "Wrong architecture/page size");
        long installed = Long.parseLong(properties.get("ro.googlebook.pad3.release_sequence"));
        require(installed > 0 && release.sequence > installed, "Release is not newer than installed native port");
        require(release.fingerprints.contains(fingerprint), "Installed native fingerprint is not allowed");
    }
    public static void guardUser(int activeUser, int packageUser, int packageUid, int requestedUid) throws IOException {
        require(activeUser >= 0 && packageUser == activeUser && packageUid > 0 && packageUid == requestedUid,
                "Active Android user or updater UID changed; retry from the active user's Settings");
    }
    public static long deviceMajor(long dev) { return ((dev >>> 32) & 0xfffff000L) | ((dev >>> 8) & 0xfffL); }
    public static long deviceMinor(long dev) { return ((dev >>> 12) & 0xffffff00L) | (dev & 0xffL); }
    public static void guardSystemDm(String name, String slot) throws IOException {
        require(("_a".equals(slot) || "_b".equals(slot)) && ("system" + slot).equals(name),
                "Mounted /system is not the exact native slot device: " + name);
    }
    public static void guardNativeBoot(Boolean dynamicInUse, Boolean gsiRunning, String dmName, String slot) throws IOException {
        guardSystemDm(dmName, slot);
        require(Boolean.FALSE.equals(dynamicInUse) && Boolean.FALSE.equals(gsiRunning),
                "Protected DSU/GSI state is active or unavailable; native OTA is blocked");
    }
    public static void guardPrivateDirectory(int uid, int gid, int mode, int expectedUid) throws IOException {
        require(uid == expectedUid && (mode & 0002) == 0 && ((mode & 0020) == 0 || gid == expectedUid),
                "Private directory ownership/mode mismatch");
    }
    public static void noSymlinks(File root, File target) throws IOException {
        Path base = root.getAbsoluteFile().toPath().normalize(), path = target.getAbsoluteFile().toPath().normalize();
        require(base.equals(root.getCanonicalFile().toPath()) && path.startsWith(base), "Private path escaped its framework directory");
        require(!Files.isSymbolicLink(base), "Symlink private directory");
        Path current = base;
        for (Path part : base.relativize(path)) {
            current = current.resolve(part);
            require(!Files.isSymbolicLink(current), "Symlink in private updater files");
        }
    }
    public static String hash(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) { return hash(in, file.length()); }
    }
    static String hash(InputStream in, long count) throws IOException {
        MessageDigest digest = digest();
        byte[] buffer = new byte[1024 * 1024];
        while (count > 0) {
            int n = in.read(buffer, 0, (int)Math.min(count, buffer.length));
            require(n > 0, "Truncated image");
            digest.update(buffer, 0, n); count -= n;
        }
        return hex(digest.digest());
    }
    static void range(HttpURLConnection connection, long start, long size) throws IOException {
        String expected = "bytes " + start + "-" + (size - 1) + "/" + size;
        require(expected.equals(connection.getHeaderField("Content-Range")), "Invalid resumed Content-Range");
    }
    public static void download(Part part, File target, Progress progress) throws IOException {
        download(part, target, progress, HTTPS);
    }
    static void download(Part part, File target, Progress progress, Connections connections) throws IOException {
        if (target.isFile() && target.length() == part.size && hash(target).equals(part.sha256)) return;
        File partial = new File(target.getPath() + ".part");
        long start = partial.isFile() ? partial.length() : 0;
        require(start <= part.size, "Partial download exceeds signed size");
        if (start < part.size) {
            HttpURLConnection connection = connect(part.url, start, connections);
            try {
                int status = connection.getResponseCode();
                require(status == 200 || status == 206, "Download HTTP " + status);
                if (status == 200) start = 0;
                else range(connection, start, part.size);
                long length = connection.getContentLengthLong();
                require(length < 0 || length == part.size - start, "Incorrect download Content-Length");
                try (InputStream in = connection.getInputStream(); FileOutputStream out = new FileOutputStream(partial, start > 0)) {
                    byte[] buffer = new byte[1024 * 1024];
                    long done = start;
                    progress.update(done, part.size);
                    for (int n; (n = in.read(buffer)) != -1;) {
                        require(done <= part.size - n, "Download exceeds signed size");
                        out.write(buffer, 0, n); done += n; progress.update(done, part.size);
                    }
                    out.getFD().sync();
                    require(done == part.size, "Incomplete download; retry to resume");
                }
            } finally { connection.disconnect(); }
        }
        if (!hash(partial).equals(part.sha256)) {
            Files.deleteIfExists(partial.toPath());
            throw new IOException("Part SHA-256 mismatch; partial removed");
        }
        Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    public static File join(Release release, File directory, Progress progress) throws IOException {
        File joined = new File(directory, "ota.zip");
        if (joined.isFile() && joined.length() == release.otaSize && hash(joined).equals(release.otaHash)) return joined;
        File temporary = new File(directory, "ota.zip.part");
        long total = 0;
        try (FileOutputStream out = new FileOutputStream(temporary)) {
            for (int i = 0; i < release.parts.size(); i++) {
                File part = new File(directory, "part-" + i);
                require(part.length() == release.parts.get(i).size && hash(part).equals(release.parts.get(i).sha256), "Part changed before joining");
                try (InputStream in = new FileInputStream(part)) {
                    byte[] buffer = new byte[1024 * 1024];
                    for (int n; (n = in.read(buffer)) != -1;) {
                        out.write(buffer, 0, n); total += n; progress.update(total, release.otaSize);
                    }
                }
            }
            out.getFD().sync();
        }
        require(total == release.otaSize && hash(temporary).equals(release.otaHash), "Joined OTA SHA-256 mismatch");
        Files.move(temporary.toPath(), joined.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        for (int i = 0; i < release.parts.size(); i++) Files.deleteIfExists(new File(directory, "part-" + i).toPath());
        return joined;
    }
    public static void verifyZip(File file, Release release) throws IOException {
        require(file.length() == release.otaSize && hash(file).equals(release.otaHash), "OTA ZIP SHA-256/size mismatch");
        try (ZipFile zip = new ZipFile(file)) {
            Set<String> names = new HashSet<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                require(names.size() < 512 && names.add(name) && !name.startsWith("/") && !name.contains("..") && !name.contains("\\"),
                        "Unsafe or duplicate ZIP member");
            }
            ZipEntry payload = zip.getEntry("payload.bin");
            require(payload != null && payload.getMethod() == ZipEntry.STORED && payload.getSize() == release.payloadSize,
                    "payload.bin must be ZIP_STORED with signed size");
            try (InputStream in = zip.getInputStream(payload)) {
                require(hash(in, release.payloadSize).equals(release.payloadHash), "ZIP payload hash mismatch");
            }
            ZipEntry properties = zip.getEntry("payload_properties.txt");
            require(properties != null, "Missing payload_properties.txt");
            try (InputStream in = zip.getInputStream(properties)) {
                String text = new String(bounded(in, 8192), StandardCharsets.UTF_8).trim();
                require(properties(text.split("\\r?\\n")).equals(properties(release.properties)), "ZIP payload properties differ from manifest");
            }
            ZipEntry metadata = zip.getEntry("META-INF/com/android/metadata");
            require(metadata != null, "Missing A/B package metadata");
            Properties values = new Properties();
            try (InputStream in = zip.getInputStream(metadata)) { values.load(new ByteArrayInputStream(bounded(in, 65536))); }
            require("AB".equals(values.getProperty("ota-type")) && "erhai".equals(values.getProperty("pre-device")), "Wrong OTA type/device");
            for (String key : Arrays.asList("ota-wipe", "ota-downgrade", "spl-downgrade"))
                require(!"yes".equals(values.getProperty(key)), "Destructive/downgrade OTA is not allowed");
        }
        metadataPrefixSize(file, release);
        try (FileInputStream in = new FileInputStream(file)) {
            in.getChannel().position(release.offset);
            require(hash(in, release.payloadSize).equals(release.payloadHash), "Signed payload offset hash mismatch");
            in.getChannel().position(release.offset);
            require(hash(in, release.metadataSize).equals(release.metadataHash), "Payload metadata hash mismatch");
        }
    }
    public static int metadataPrefixSize(File file, Release release) throws IOException {
        require(release.offset >= 0 && release.payloadSize >= 24 && release.offset <= file.length() - release.payloadSize,
                "Payload range is outside ZIP");
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            in.seek(release.offset);
            require(in.readInt() == 0x43724155 && in.readLong() == 2, "Payload offset/header is not CrAU v2");
            long manifestSize = in.readLong();
            long signatureSize = Integer.toUnsignedLong(in.readInt());
            require(manifestSize > 0 && release.metadataSize >= 24 && release.metadataSize <= 16 * 1024 * 1024
                    && manifestSize == release.metadataSize - 24, "Payload metadata boundary mismatch");
            require(signatureSize > 0 && signatureSize <= 16 * 1024 * 1024 - release.metadataSize
                    && signatureSize <= release.payloadSize - release.metadataSize, "Payload metadata signature outside bounded prefix");
            return (int)(release.metadataSize + signatureSize);
        }
    }
}
