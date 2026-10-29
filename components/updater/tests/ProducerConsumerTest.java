package org.googlebook.pad3.updater;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Consume the current Python producer's keyless format fixture; not a cryptographic pass. */
public final class ProducerConsumerTest {
    public static void main(String[] args) throws Exception {
        File zip = new File(args[0]);
        Properties properties = new Properties();
        try (InputStream in = new FileInputStream(args[1])) { properties.load(in); }
        UpdateCore.Release release = new UpdateCore.Release();
        release.version = "KEYLESS-PRODUCER-FIXTURE"; release.sequence = 2; release.published = 100; release.expires = 200;
        release.baseProfile = "erhai-crdroid-20261025"; release.fingerprints.add("fixture");
        release.sourceSlot = args[4];
        release.otaSize = zip.length(); release.otaHash = UpdateCore.hash(zip);
        release.offset = Long.parseLong(args[2]); release.payloadSize = Long.parseLong(properties.getProperty("FILE_SIZE"));
        release.metadataSize = Long.parseLong(properties.getProperty("METADATA_SIZE"));
        release.payloadHash = UpdateCore.hex(Base64.getDecoder().decode(properties.getProperty("FILE_HASH")));
        release.metadataHash = UpdateCore.hex(Base64.getDecoder().decode(properties.getProperty("METADATA_HASH")));
        release.properties = new String[4];
        int i = 0;
        for (String key : new String[]{"FILE_HASH", "FILE_SIZE", "METADATA_HASH", "METADATA_SIZE"}) release.properties[i++] = key + "=" + properties.getProperty(key);
        release.parts.add(new UpdateCore.Part("https://github.com/thekozugroup/googlebook-pad3-os/releases/download/fixture/part00", zip.length(), release.otaHash));
        release.validate(150);
        UpdateCore.verifyZip(zip, release);
        int signatureSize = Integer.parseInt(args[3]);
        int prefix = UpdateCore.metadataPrefixSize(zip, release);
        UpdateCore.require(prefix == release.metadataSize + signatureSize && signatureSize > 0, "Metadata signature was omitted from native preflight prefix");
        try (RandomAccessFile in = new RandomAccessFile(zip, "r")) {
            in.seek(release.offset);
            byte[] actual = new byte[prefix]; in.readFully(actual);
            UpdateCore.require(actual.length > release.metadataSize, "Truncated preflight prefix");
        }
        System.out.println("PRODUCER_CONSUMER_FORMAT_PASS offset=" + release.offset + " metadata=" + release.metadataSize + " signature=" + signatureSize);
    }
}
