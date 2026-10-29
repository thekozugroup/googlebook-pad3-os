package org.googlebook.pad3.updater;

import java.util.*;
import org.json.*;

/** Object-model fixtures exercise the real feed consumer without signing a feed. */
public final class ManifestCodecTest {
    static int checks;
    interface Action { void run() throws Exception; }
    static void check(boolean yes) { checks++; if (!yes) throw new AssertionError("check " + checks); }
    static void fails(Action action) throws Exception {
        try { action.run(); }
        catch (Exception expected) {
            String message = expected.getMessage();
            check(message != null && (message.contains("source_slot") || message.contains("source slot")));
            return;
        }
        throw new AssertionError("Expected source-slot rejection");
    }
    static JSONObject fixture(Object slot) throws Exception {
        String hash = "00".repeat(32), encoded = Base64.getEncoder().encodeToString(new byte[32]);
        long now = System.currentTimeMillis() / 1000;
        return new JSONObject().put("schema", 1).put("device", "erhai").put("channel", "stable")
                .put("version", "SOURCE-SLOT-HOST-FIXTURE").put("sequence", 2)
                .put("published_at", now - 60).put("expires_at", now + 3600)
                .put("base_profile", "erhai-crdroid-20261025").put("source_slot", slot)
                .put("pre_build_fingerprints", new JSONArray().put("fixture"))
                .put("ota", new JSONObject().put("size", 1024).put("sha256", hash)
                        .put("parts", new JSONArray().put(new JSONObject()
                                .put("url", "https://github.com/thekozugroup/googlebook-pad3-os/releases/download/fixture/part00")
                                .put("size", 1024).put("sha256", hash))))
                .put("payload", new JSONObject().put("offset", 0).put("size", 512).put("sha256", hash)
                        .put("metadata_size", 25).put("metadata_sha256", hash)
                        .put("properties", new JSONArray().put("FILE_HASH=" + encoded).put("FILE_SIZE=512")
                                .put("METADATA_HASH=" + encoded).put("METADATA_SIZE=25")));
    }
    static Map<String,String> properties(String slot) {
        Map<String,String> result = new HashMap<>();
        result.put("ro.googlebook.pad3.native", "1"); result.put("ro.googlebook.pad3.device", "erhai");
        result.put("ro.googlebook.pad3.base_profile", "erhai-crdroid-20261025"); result.put("ro.gsid.image_running", "0");
        result.put("ro.build.ab_update", "true"); result.put("ro.virtual_ab.enabled", "true");
        result.put("ro.boot.slot_suffix", slot); result.put("ro.googlebook.pad3.release_sequence", "1");
        return result;
    }
    public static void main(String[] args) throws Exception {
        for (String slot : new String[]{"_b", "_a"}) {
            UpdateCore.Release release = ManifestCodec.release(fixture(slot));
            check(slot.equals(release.sourceSlot));
            UpdateCore.guardNative(release, properties(slot), "fixture", new String[]{"arm64-v8a"}, 4096); checks++;
            String opposite = slot.equals("_b") ? "_a" : "_b";
            fails(() -> UpdateCore.guardNative(release, properties(opposite), "fixture", new String[]{"arm64-v8a"}, 4096));
        }
        JSONObject missing = fixture("_b"); missing.remove("source_slot");
        fails(() -> ManifestCodec.release(missing));
        for (Object invalid : new Object[]{JSONObject.NULL, 1, true, "", "a", "b", "_c", "_B", " _b", "_b "})
            fails(() -> ManifestCodec.release(fixture(invalid)));
        System.out.println("MANIFEST_SOURCE_SLOT_CHECKS_PASSED=" + checks);
    }
}
