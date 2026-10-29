package org.googlebook.pad3.updater;

import android.os.Looper;
import android.os.SELinux;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Runs only the installed APK's fixed wm operations under existing owner-authorized root. */
public final class RootWindowMode {
    private static String run(String[] command) throws Exception {
        java.lang.Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        try {
            UpdateCore.require(process.waitFor(5, TimeUnit.SECONDS), "Window manager timed out");
            try (InputStream in = process.getInputStream()) {
                String output = new String(UpdateCore.bounded(in, 4096), StandardCharsets.UTF_8);
                UpdateCore.require(process.exitValue() == 0, "Window manager rejected layout request");
                return output;
            }
        } finally { process.destroy(); }
    }
    public static void main(String[] args) {
        try {
            UpdateCore.require(android.os.Process.myUid() == 0, "SukiSU root authorization is required");
            UpdateCore.require(SELinux.isSELinuxEnforced() && "u:r:ksu:s0".equals(SELinux.getContext()),
                    "Expected the authorized ksu domain with SELinux enforcing");
            int uid = WindowMode.requestedUid(args);
            UpdateCore.require(new File(System.getenv("CLASSPATH")).getCanonicalFile()
                    .equals(new File(RootInstaller.APK).getCanonicalFile()), "Helper must run from the installed built-in APK");
            if (Looper.myLooper() == null) Looper.prepareMainLooper();
            NativeIdentity.requireNative();
            ActiveProfile profile = ActiveProfile.resolve(uid, false);
            int mode = WindowMode.parse(run(WindowMode.query()));
            if (args[0].equals("toggle")) {
                int target = mode == 1 ? 5 : 1;
                NativeIdentity.requireNative();
                profile.ensureActive();
                run(WindowMode.select(target));
                mode = WindowMode.parse(run(WindowMode.query()));
                UpdateCore.require(mode == target, "Layout change was not confirmed");
            }
            profile.ensureActive();
            System.out.println(WindowMode.label(mode));
            System.exit(0);
        } catch (Throwable error) {
            System.out.println("FAILED " + String.valueOf(error.getMessage()).replace('\n', ' ').replace('\r', ' '));
            System.exit(1);
        }
    }
}
