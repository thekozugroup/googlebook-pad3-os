package org.googlebook.pad3.updater;

public final class PhoneCompatibilityTest {
    private static int checks;
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Phone compatibility boundary failed");
        checks++;
    }
    private static void rejected(String... args) {
        try { RootPhoneCompatibility.caller(args); throw new AssertionError("UID accepted"); }
        catch (Exception expected) { checks++; }
    }
    private static void rejectedModule(String hash, String targets) {
        try { RootPhoneCompatibility.moduleIdentity(hash, targets); throw new AssertionError("Module accepted"); }
        catch (Exception expected) { checks++; }
    }
    private static final class Child extends java.lang.Process {
        boolean closed, destroyed;
        @Override public java.io.OutputStream getOutputStream() {
            return new java.io.ByteArrayOutputStream() { @Override public void close() { closed = true; } };
        }
        @Override public java.io.InputStream getInputStream() { return new java.io.ByteArrayInputStream(new byte[0]); }
        @Override public java.io.InputStream getErrorStream() { return getInputStream(); }
        @Override public int waitFor() { return 0; }
        @Override public int exitValue() { return 0; }
        @Override public void destroy() { destroyed = true; }
        @Override public java.lang.Process destroyForcibly() { destroy(); return this; }
    }
    public static void main(String[] args) throws Exception {
        check(RootPhoneCompatibility.caller(new String[]{"1010234"}) == 1010234);
        check(RootPhoneCompatibility.caller(new String[]{"1110234"}) == 1110234);
        for (String bad : new String[]{"0", "1000", "2000", "10234", "1000000", "-1", "2147483648", "1;id", "", " 1010234"}) rejected(bad);
        rejected(); rejected("1010234", "extra");
        String targets = "com.android.vending!\ncom.google.ambient.streaming!\ncom.android.providers.settings!\n";
        RootPhoneCompatibility.moduleIdentity(RootPhoneCompatibility.MODULE_SHA, targets); checks++;
        rejectedModule("0".repeat(64), targets);
        rejectedModule(RootPhoneCompatibility.MODULE_SHA, "com.google.ambient.streaming!\n");
        rejectedModule(RootPhoneCompatibility.MODULE_SHA, "com.android.providers.settings!\n");
        rejectedModule(RootPhoneCompatibility.MODULE_SHA, targets.replace("!", ""));
        rejectedModule(RootPhoneCompatibility.MODULE_SHA, targets.replace("com.google.ambient.streaming!", "#com.google.ambient.streaming!"));
        check(RootPhoneCompatibility.configurationChecked(0, "PHONE_CONFIG_CHECKED\n"));
        check(RootPhoneCompatibility.configurationChecked(0, "some native output\r\nPHONE_CONFIG_CHECKED\r\n"));
        check(!RootPhoneCompatibility.configurationChecked(1, "PHONE_CONFIG_CHECKED\n"));
        check(!RootPhoneCompatibility.configurationChecked(0, "NOT_PHONE_CONFIG_CHECKED\n"));
        check(!RootPhoneCompatibility.configurationChecked(0, "NATIVE_PUBLISH_CALL_COMPLETED_VERIFY_SNAPSHOT_SEPARATELY\n"));
        check(!RootPhoneCompatibility.configurationChecked(0, ""));
        PhoneCompatibilityJob.Run cancelled = new PhoneCompatibilityJob.Run();
        cancelled.cancel(); check(cancelled.cancelled);
        try { cancelled.start(new ProcessBuilder("must-not-launch-cancelled-fixture")); throw new AssertionError("Cancelled launch accepted"); }
        catch (java.io.IOException expected) { check("Phone check cancelled".equals(expected.getMessage())); }
        PhoneCompatibilityJob.Run running = new PhoneCompatibilityJob.Run();
        Child child = new Child(); running.child = child; running.cancel();
        check(running.cancelled); check(child.closed); check(child.destroyed);
        System.out.println("PHONE_COMPATIBILITY_CHECKS_PASSED=" + checks);
    }
}
