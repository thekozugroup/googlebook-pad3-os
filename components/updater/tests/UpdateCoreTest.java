package org.googlebook.pad3.updater;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.zip.*;

/** Host-only fixtures. Synthetic CrAU bytes are not signed/installable OTAs. */
public final class UpdateCoreTest {
    static int checks;
    interface Action { void run() throws Exception; }
    static void check(boolean yes) { checks++; if (!yes) throw new AssertionError("check " + checks); }
    static void fails(Action action) throws Exception {
        checks++;
        try { action.run(); } catch (IOException | IllegalArgumentException | ArithmeticException expected) { return; }
        throw new AssertionError("Expected failure at " + checks);
    }
    static String hash(byte[] bytes) throws Exception { return UpdateCore.hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static final String URL = "https://github.com/thekozugroup/googlebook-pad3-os/releases/download/test/ota.part00";

    static void signature() throws Exception {
        // Public verification vector only: RFC 7515 Appendix A.2. No private key or key generation.
        String n = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
        byte[] key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode(n)), BigInteger.valueOf(65537))).getEncoded();
        String input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        String signature = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8), sig = Base64.getUrlDecoder().decode(signature);
        check(new String(UpdateCore.verifiedFeed(key, bytes, sig), StandardCharsets.UTF_8).equals(input));
        fails(() -> UpdateCore.verifiedFeed(key, (input + " ").getBytes(StandardCharsets.UTF_8), sig));
        fails(() -> UpdateCore.verifiedFeed(new byte[0], bytes, sig));
        fails(() -> UpdateCore.verifiedFeed(key, bytes, new byte[]{1,2,3}));
        fails(() -> UpdateCore.verifiedFeed(key, "[]".getBytes(StandardCharsets.UTF_8), sig));
        fails(() -> UpdateCore.verifiedFeed(key, new byte[UpdateCore.FEED_LIMIT + 1], sig));
    }
    static byte[] payload() {
        ByteBuffer data = ByteBuffer.allocate(256).order(ByteOrder.BIG_ENDIAN);
        data.putInt(0x43724155).putLong(2).putLong(1).putInt(1).put((byte)1).put((byte)2);
        return data.array();
    }
    static void member(ZipOutputStream zip, String name, byte[] bytes, boolean stored) throws Exception {
        ZipEntry entry = new ZipEntry(name);
        if (stored) {
            CRC32 crc = new CRC32(); crc.update(bytes);
            entry.setMethod(ZipEntry.STORED); entry.setSize(bytes.length); entry.setCompressedSize(bytes.length); entry.setCrc(crc.getValue());
        }
        zip.putNextEntry(entry); zip.write(bytes); zip.closeEntry();
    }
    static UpdateCore.Release fixture(File directory, boolean compressed, String device, String extra) throws Exception {
        byte[] payload = payload();
        UpdateCore.Release release = new UpdateCore.Release();
        release.version = "TEST-FIXTURE-NOT-INSTALLABLE"; release.sequence = 2;
        release.published = 100; release.expires = 200;
        release.baseProfile = "erhai-crdroid-20261025"; release.fingerprints.add("fixture-fingerprint");
        release.sourceSlot = "_b";
        release.payloadSize = payload.length; release.metadataSize = 25;
        release.payloadHash = hash(payload); release.metadataHash = hash(Arrays.copyOf(payload, 25));
        release.properties = new String[]{"FILE_HASH=" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(payload)),
                "FILE_SIZE=256", "METADATA_HASH=" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(payload, 25))), "METADATA_SIZE=25"};
        File zip = new File(directory, "fixture.zip");
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zip))) {
            member(out, "payload.bin", payload, !compressed);
            member(out, "payload_properties.txt", String.join("\n", release.properties).getBytes(StandardCharsets.UTF_8), false);
            member(out, "META-INF/com/android/metadata", ("ota-type=AB\npre-device=" + device + "\n").getBytes(StandardCharsets.UTF_8), false);
            if (extra != null) member(out, extra, new byte[]{1}, false);
        }
        byte[] whole = Files.readAllBytes(zip.toPath());
        release.offset = 30 + "payload.bin".length();
        release.otaSize = zip.length(); release.otaHash = hash(whole);
        release.parts.add(new UpdateCore.Part(URL, whole.length, release.otaHash));
        return release;
    }
    static void packages(File root) throws Exception {
        File directory = new File(root, "zip"); check(directory.mkdir());
        final UpdateCore.Release release = fixture(directory, false, "erhai", null);
        release.validate(150); checks++;
        UpdateCore.verifyZip(new File(directory, "fixture.zip"), release); checks++;
        check(UpdateCore.metadataPrefixSize(new File(directory, "fixture.zip"), release) == 26);
        try (RandomAccessFile in = new RandomAccessFile(new File(directory, "fixture.zip"), "rw")) {
            in.seek(release.offset + 20); in.writeInt(-1);
            fails(() -> UpdateCore.metadataPrefixSize(new File(directory, "fixture.zip"), release));
            in.seek(release.offset + 20); in.writeInt(0);
            fails(() -> UpdateCore.metadataPrefixSize(new File(directory, "fixture.zip"), release));
            in.seek(release.offset + 20); in.writeInt(1);
        }
        release.validate(199); checks++;
        fails(() -> release.validate(200));
        long offset = release.offset; release.offset++;
        fails(() -> UpdateCore.verifyZip(new File(directory, "fixture.zip"), release)); release.offset = offset;
        release.sequence = 0; fails(() -> release.validate(150)); release.sequence = 2;
        release.baseProfile = "unknown"; fails(() -> release.validate(150)); release.baseProfile = "erhai-crdroid-20261025";
        for (String slot : new String[]{null, "", "a", "b", "_c", "_A", " _b", "_b "}) {
            release.sourceSlot = slot; fails(() -> release.validate(150));
        }
        release.sourceSlot = "_b";
        release.metadataSize++; fails(() -> release.validate(150)); release.metadataSize--;
        release.properties[3] = "POWERWASH=1"; fails(() -> release.validate(150));
        final UpdateCore.Release wrongDevice = fixture(directory, false, "ruby", null);
        fails(() -> UpdateCore.verifyZip(new File(directory, "fixture.zip"), wrongDevice));
        final UpdateCore.Release compressed = fixture(directory, true, "erhai", null);
        fails(() -> UpdateCore.verifyZip(new File(directory, "fixture.zip"), compressed));
        final UpdateCore.Release traversal = fixture(directory, false, "erhai", "../outside");
        fails(() -> UpdateCore.verifyZip(new File(directory, "fixture.zip"), traversal));
        final UpdateCore.Release joinedRelease = fixture(directory, false, "erhai", null);
        byte[] whole = Files.readAllBytes(new File(directory, "fixture.zip").toPath());
        int split = whole.length / 2;
        byte[] first = Arrays.copyOfRange(whole, 0, split), second = Arrays.copyOfRange(whole, split, whole.length);
        joinedRelease.parts = Arrays.asList(new UpdateCore.Part(URL, first.length, hash(first)), new UpdateCore.Part(URL, second.length, hash(second)));
        Files.write(new File(directory, "part-0").toPath(), first); Files.write(new File(directory, "part-1").toPath(), second);
        File joined = UpdateCore.join(joinedRelease, directory, (d,t) -> { });
        check(UpdateCore.hash(joined).equals(joinedRelease.otaHash));
        check(!new File(directory, "part-0").exists()); check(!new File(directory, "part-1").exists());
        final UpdateCore.Release valid = joinedRelease;
        try (RandomAccessFile file = new RandomAccessFile(joined, "rw")) { file.seek(0); file.write(0); }
        fails(() -> UpdateCore.verifyZip(joined, valid));
        fails(() -> new UpdateCore.Part(URL, UpdateCore.GIB + 1, valid.otaHash));
        fails(() -> new UpdateCore.Part("https://evil.test/ota", 1, valid.otaHash));
        Map<String,String> properties = new HashMap<>();
        properties.put("ro.googlebook.pad3.native", "1"); properties.put("ro.googlebook.pad3.device", "erhai");
        properties.put("ro.googlebook.pad3.base_profile", "erhai-crdroid-20261025"); properties.put("ro.gsid.image_running", "0");
        properties.put("ro.build.ab_update", "true"); properties.put("ro.virtual_ab.enabled", "true");
        properties.put("ro.boot.slot_suffix", "_b"); properties.put("ro.googlebook.pad3.release_sequence", "1");
        UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"arm64-v8a"}, 4096); checks++;
        for (String slot : new String[]{"_b", "_a"}) {
            valid.sourceSlot = slot;
            properties.put("ro.boot.slot_suffix", slot);
            UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"arm64-v8a"}, 4096); checks++;
            properties.put("ro.boot.slot_suffix", slot.equals("_b") ? "_a" : "_b");
            fails(() -> UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"arm64-v8a"}, 4096));
        }
        valid.sourceSlot = "_b"; properties.put("ro.boot.slot_suffix", "_b");
        for (String[] change : new String[][]{{"ro.googlebook.pad3.native","0"},{"ro.googlebook.pad3.device","ruby"},
                {"ro.googlebook.pad3.base_profile","unknown"},{"ro.gsid.image_running","1"},{"ro.build.ab_update","false"},
                {"ro.virtual_ab.enabled","false"},{"ro.boot.slot_suffix",""},{"ro.googlebook.pad3.release_sequence","2"},
                {"ro.googlebook.pad3.release_sequence","not-an-integer"}}) {
            String previous = properties.put(change[0], change[1]);
            fails(() -> UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"arm64-v8a"}, 4096));
            properties.put(change[0], previous);
        }
        fails(() -> UpdateCore.guardNative(valid, properties, "wrong-fingerprint", new String[]{"arm64-v8a"}, 4096));
        fails(() -> UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"armeabi-v7a"}, 4096));
        fails(() -> UpdateCore.guardNative(valid, properties, "fixture-fingerprint", new String[]{"arm64-v8a"}, 16384));
        UpdateCore.Release large = new UpdateCore.Release();
        large.version = "SIZE-ONLY-FIXTURE"; large.sequence = 3; large.published = 100; large.expires = 200;
        large.baseProfile = valid.baseProfile; large.fingerprints = valid.fingerprints;
        large.sourceSlot = "_a";
        large.otaSize = 4 * UpdateCore.GIB; large.otaHash = valid.otaHash;
        large.offset = 2 * UpdateCore.GIB + 41; large.payloadSize = UpdateCore.GIB;
        large.payloadHash = valid.payloadHash; large.metadataHash = valid.metadataHash; large.metadataSize = valid.metadataSize;
        large.properties = valid.properties.clone(); large.properties[1] = "FILE_SIZE=" + UpdateCore.GIB;
        for (int i = 0; i < 4; i++) large.parts.add(new UpdateCore.Part(URL, UpdateCore.GIB, valid.otaHash));
        large.validate(150); checks++; // Exercises signed 64-bit ranges without allocating/downloading gigabytes.
    }
    static final class Response extends HttpURLConnection {
        final byte[] body; final int code; final String range; final long length;
        Response(byte[] body, int code, String range, long length) throws Exception { super(new URL(URL)); this.body=body; this.code=code; this.range=range; this.length=length; }
        @Override public int getResponseCode() { return code; }
        @Override public String getHeaderField(String name) { return name.equals("Content-Range") ? range : null; }
        @Override public long getContentLengthLong() { return length; }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(body); }
        @Override public void disconnect() { }
        @Override public boolean usingProxy() { return false; }
        @Override public void connect() { }
    }
    static void transport(File root) throws Exception {
        byte[] bytes = "0123456789".getBytes(StandardCharsets.US_ASCII);
        UpdateCore.Part part = new UpdateCore.Part(URL, bytes.length, hash(bytes));
        File target = new File(root, "download");
        File partial = new File(target.getPath() + ".part");
        Files.write(partial.toPath(), Arrays.copyOf(bytes, 3));
        Response resumed = new Response(Arrays.copyOfRange(bytes, 3, 10), 206, "bytes 3-9/10", 7);
        UpdateCore.download(part, target, (d,t) -> { }, url -> resumed);
        check(resumed.getRequestProperty("Range").equals("bytes=3-"));
        check(UpdateCore.hash(target).equals(part.sha256)); check(!partial.exists());
        Files.delete(target.toPath()); Files.write(partial.toPath(), Arrays.copyOf(bytes, 3));
        Response ignoredRange = new Response(bytes, 200, null, 10);
        UpdateCore.download(part, target, (d,t) -> { }, url -> ignoredRange);
        check(target.length() == 10); check(UpdateCore.hash(target).equals(part.sha256));
        Files.delete(target.toPath()); Files.write(partial.toPath(), Arrays.copyOf(bytes, 3));
        Response badRange = new Response(bytes, 206, "bytes 0-9/10", 10);
        fails(() -> UpdateCore.download(part, target, (d,t) -> { }, url -> badRange));
        Files.delete(partial.toPath());
        Response tooLarge = new Response(new byte[11], 200, null, -1);
        fails(() -> UpdateCore.download(part, target, (d,t) -> { }, url -> tooLarge));
        Files.deleteIfExists(partial.toPath());
        Response badHash = new Response(new byte[10], 200, null, 10);
        fails(() -> UpdateCore.download(part, target, (d,t) -> { }, url -> badHash)); check(!partial.exists());
        Response shortBody = new Response(new byte[3], 200, null, -1);
        fails(() -> UpdateCore.download(part, target, (d,t) -> { }, url -> shortBody)); check(partial.length() == 3);
        fails(() -> UpdateCore.bounded(new ByteArrayInputStream(new byte[17]), 16));
        fails(() -> UpdateCore.httpsUrl("http://github.com/ota"));
        fails(() -> UpdateCore.httpsUrl("https://owner:token@github.com/ota"));
        fails(() -> UpdateCore.connect("https://evil.test/ota", 0, url -> shortBody));
    }
    static void profiles(File root) throws Exception {
        UpdateCore.guardUser(10, 10, 1010428, 1010428); checks++;
        UpdateCore.guardUser(0, 0, 10428, 10428); checks++;
        fails(() -> UpdateCore.guardUser(10, 0, 10428, 1010428));
        fails(() -> UpdateCore.guardUser(0, 10, 1010428, 1010428)); // Switch from UI user 10 to user 0.
        fails(() -> UpdateCore.guardUser(11, 10, 1010428, 1010428));
        fails(() -> UpdateCore.guardUser(10, 10, 1010428, 10428));
        fails(() -> UpdateCore.guardUser(-1, 10, 1010428, 1010428));
        UpdateCore.guardPrivateDirectory(1010428, 1010428, 0771, 1010428); checks++;
        UpdateCore.guardPrivateDirectory(10428, 10428, 0700, 10428); checks++;
        fails(() -> UpdateCore.guardPrivateDirectory(10428, 10428, 0700, 1010428));
        fails(() -> UpdateCore.guardPrivateDirectory(1010428, 2001, 0771, 1010428));
        fails(() -> UpdateCore.guardPrivateDirectory(1010428, 1010428, 0777, 1010428));
        File data = new File(root, "profile-files").getCanonicalFile(); check(data.mkdir());
        File normal = new File(data, "selected-feed.json"); Files.write(normal.toPath(), new byte[]{1});
        UpdateCore.noSymlinks(data, normal); checks++;
        File link = new File(data, "linked-feed"); Files.createSymbolicLink(link.toPath(), normal.toPath());
        fails(() -> UpdateCore.noSymlinks(data, link));
        File linkedDirectory = new File(data, "linked-dir"); Files.createSymbolicLink(linkedDirectory.toPath(), data.toPath());
        fails(() -> UpdateCore.noSymlinks(data, new File(linkedDirectory, "selected-feed.json")));
        fails(() -> UpdateCore.noSymlinks(data, new File(data, "../other-profile/selected-feed.json")));
    }
    static void nativeBoot() throws Exception {
        UpdateCore.guardNativeBoot(false, false, "system_a", "_a"); checks++;
        UpdateCore.guardNativeBoot(false, false, "system_b", "_b"); checks++;
        for (String name : new String[]{"system_gsi", "system_gsi_a", "system", "overlay", "system_b-verity", "system_a", ""})
            fails(() -> UpdateCore.guardNativeBoot(false, false, name, "_b"));
        fails(() -> UpdateCore.guardNativeBoot(true, false, "system_b", "_b"));
        fails(() -> UpdateCore.guardNativeBoot(false, true, "system_b", "_b"));
        fails(() -> UpdateCore.guardNativeBoot(null, false, "system_b", "_b"));
        fails(() -> UpdateCore.guardNativeBoot(false, null, "system_b", "_b"));
        fails(() -> UpdateCore.guardNativeBoot(false, false, "system_b", ""));
        long dev = (253L << 8) | 17;
        check(UpdateCore.deviceMajor(dev) == 253 && UpdateCore.deviceMinor(dev) == 17);
        long major = 0x12345, minor = 0x123456;
        long high = ((major & 0xfffff000L) << 32) | ((major & 0xfffL) << 8)
                | ((minor & 0xffffff00L) << 12) | (minor & 0xff);
        check(UpdateCore.deviceMajor(high) == major && UpdateCore.deviceMinor(high) == minor);
    }
    public static void main(String[] args) throws Exception {
        signature(); packages(new File(args[0])); transport(new File(args[0])); profiles(new File(args[0])); nativeBoot();
        System.out.println("CORE_CHECKS_PASSED=" + checks);
    }
}
