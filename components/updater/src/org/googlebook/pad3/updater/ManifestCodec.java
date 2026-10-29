package org.googlebook.pad3.updater;

import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.*;

final class ManifestCodec {
    static String string(JSONObject object, String key) throws Exception {
        Object value = object.get(key);
        UpdateCore.require(value instanceof String, "Expected string: " + key);
        return (String)value;
    }
    static long number(JSONObject object, String key) throws Exception {
        Object value = object.get(key);
        UpdateCore.require(value instanceof Integer || value instanceof Long, "Expected integer: " + key);
        return ((Number)value).longValue();
    }
    static UpdateCore.Release select(byte[] feed, byte[] signature, byte[] publicKey, String fingerprint) throws Exception {
        // Verify the original transport bytes before any JSON parser can transform them.
        byte[] verified = UpdateCore.verifiedFeed(publicKey, feed, signature);
        JSONArray entries = new JSONArray(new String(verified, StandardCharsets.UTF_8));
        UpdateCore.require(entries.length() <= 16, "Too many feed entries");
        UpdateCore.Release newest = null;
        for (int i = 0; i < entries.length(); i++) {
            UpdateCore.Release release = release(entries.getJSONObject(i));
            if (release.fingerprints.contains(fingerprint) && (newest == null || release.sequence > newest.sequence)) newest = release;
        }
        return newest;
    }
    static UpdateCore.Release release(JSONObject object) throws Exception {
        UpdateCore.require(number(object, "schema") == 1 && string(object, "device").equals("erhai")
                && string(object, "channel").equals("stable"), "Unsupported manifest schema/device/channel");
        UpdateCore.Release result = new UpdateCore.Release();
        result.version = string(object, "version"); result.sequence = number(object, "sequence");
        result.published = number(object, "published_at"); result.expires = number(object, "expires_at");
        result.baseProfile = string(object, "base_profile");
        result.sourceSlot = string(object, "source_slot");
        JSONArray fingerprints = object.getJSONArray("pre_build_fingerprints");
        UpdateCore.require(fingerprints.length() <= 16, "Too many fingerprints");
        for (int i = 0; i < fingerprints.length(); i++) {
            UpdateCore.require(fingerprints.get(i) instanceof String, "Invalid fingerprint");
            result.fingerprints.add((String)fingerprints.get(i));
        }
        JSONObject ota = object.getJSONObject("ota"), payload = object.getJSONObject("payload");
        result.otaSize = number(ota, "size"); result.otaHash = string(ota, "sha256");
        JSONArray parts = ota.getJSONArray("parts");
        UpdateCore.require(parts.length() <= 32, "Too many OTA parts");
        for (int i = 0; i < parts.length(); i++) {
            JSONObject part = parts.getJSONObject(i);
            result.parts.add(new UpdateCore.Part(string(part, "url"), number(part, "size"), string(part, "sha256")));
        }
        result.offset = number(payload, "offset"); result.payloadSize = number(payload, "size");
        result.payloadHash = string(payload, "sha256"); result.metadataSize = number(payload, "metadata_size");
        result.metadataHash = string(payload, "metadata_sha256");
        JSONArray properties = payload.getJSONArray("properties");
        UpdateCore.require(properties.length() == 4, "Require four payload properties");
        result.properties = new String[4];
        for (int i = 0; i < 4; i++) {
            UpdateCore.require(properties.get(i) instanceof String, "Invalid property");
            result.properties[i] = (String)properties.get(i);
        }
        result.validate(System.currentTimeMillis() / 1000);
        return result;
    }
}
