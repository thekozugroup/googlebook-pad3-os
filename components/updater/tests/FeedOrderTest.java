package org.googlebook.pad3.updater;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** SDK JSON classes throw on a host JVM: reaching them before verification fails this test. */
public final class FeedOrderTest {
    public static void main(String[] args) throws Exception {
        byte[] key = Files.readAllBytes(Path.of(args[0]));
        byte[] feed = "[ { \"schema\" : 1 } ]\n".getBytes(StandardCharsets.UTF_8);
        int checks = 0;
        for (byte[] candidate : new byte[][]{key, new byte[0]}) {
            try {
                ManifestCodec.select(feed, new byte[384], candidate, "fixture");
                throw new AssertionError("Unauthenticated feed reached JSON parsing");
            } catch (IOException expected) { checks++; }
        }
        System.out.println("SIGNATURE_BEFORE_JSON_CHECKS_PASSED=" + checks);
    }
}
