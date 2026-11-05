package org.googlebook.pad3.updater;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Looper;
import android.os.SELinux;
import android.os.UserHandle;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicReference;

/** Uses the installed owner's module and native GMS APIs; never handles a keybox. */
public final class RootPhoneCompatibility {
    private static final String MODULE = "/data/adb/modules/tricky_store";
    static final String MODULE_SHA = "9423c17ede744ce2ad2a29e28d9a52560da87a7e78903c27888855aea7da0798";

    static int caller(String[] args) throws Exception {
        UpdateCore.require(args.length == 1 && args[0].matches("[0-9]{1,10}"), "Invalid caller UID");
        int uid = Integer.parseInt(args[0]);
        UpdateCore.require(uid / 100000 > 0 && uid % 100000 >= 10000, "An unlocked UI app user is required");
        return uid;
    }
    static void moduleIdentity(String digest, String targets) throws Exception {
        UpdateCore.require(MODULE_SHA.equals(digest), "Unreviewed phone compatibility module");
        HashSet<String> lines = new HashSet<>(Arrays.asList(targets.split("\\r?\\n")));
        UpdateCore.require(lines.contains("com.google.ambient.streaming!") && lines.contains("com.android.providers.settings!"),
                "Phone compatibility module scope is missing");
    }
    static boolean configurationChecked(int exit, String output) {
        return exit == 0 && Arrays.asList(output.split("\\r?\\n")).contains("PHONE_CONFIG_CHECKED");
    }
    private static File checkedFile(String path, long limit) throws Exception {
        File file = new File(path);
        StructStat stat = Os.lstat(file.getPath());
        UpdateCore.require(file.getCanonicalPath().equals(file.getPath()) && !Files.isSymbolicLink(file.toPath())
                && OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == 0 && (stat.st_mode & 0022) == 0
                && stat.st_size > 0 && stat.st_size <= limit, "Unsafe module file");
        return file;
    }
    private static void cancel(AtomicReference<java.lang.Process> running, String message) {
        synchronized (running) {
            java.lang.Process child = running.get(); if (child != null) child.destroyForcibly();
            System.err.println(message); System.exit(75);
        }
    }
    public static void main(String[] args) {
        AtomicReference<java.lang.Process> running = new AtomicReference<>();
        Thread timeout = new Thread(() -> {
            try { Thread.sleep(80000); } catch (InterruptedException done) { return; }
            cancel(running, "PHONE_COMPAT_TIMEOUT");
        }, "PhoneCompatDeadline");
        timeout.setDaemon(true); timeout.start();
        try {
            int uid = caller(args);
            UpdateCore.require(Os.getuid() == 0 && SELinux.isSELinuxEnforced() && "u:r:ksu:s0".equals(SELinux.getContext()),
                    "Authorized enforcing SukiSU root is required");
            UpdateCore.require(new File(System.getenv("CLASSPATH")).getCanonicalFile().equals(new File(RootInstaller.APK).getCanonicalFile()),
                    "Built-in updater code is required");
            NativeIdentity.requireNative();
            if (Looper.myLooper() == null) Looper.prepareMainLooper();
            ActiveProfile profile = ActiveProfile.resolve(uid, false);
            UpdateCore.require(!new File(MODULE, "disable").exists() && !new File(MODULE, "remove").exists(), "Module is inactive");
            moduleIdentity(UpdateCore.hash(checkedFile(MODULE + "/classes.dex", 4 * 1024 * 1024)),
                    new String(RootInstaller.read(checkedFile("/data/adb/tricky_store/target.txt", 65536), 65536), StandardCharsets.UTF_8));
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Object thread = threadClass.getMethod("currentActivityThread").invoke(null);
            Context system = (Context)threadClass.getMethod("getSystemContext").invoke(thread);
            UserHandle user = (UserHandle)UserHandle.class.getMethod("of", int.class).invoke(null, profile.packageUser);
            Context gms = (Context)Context.class.getMethod("createPackageContextAsUser", String.class, int.class, UserHandle.class)
                    .invoke(system, "com.google.android.gms", 0, user);
            ApplicationInfo info = gms.getApplicationInfo();
            java.lang.reflect.Method verify = Class.forName("NativeConfigRepair").getDeclaredMethod("verifyArtifact", File.class);
            verify.setAccessible(true); verify.invoke(null, new File(info.sourceDir));
            // Closing the caller's stdin cancels root work even after su changes UID.
            Thread caller = new Thread(() -> {
                try { while (System.in.read() != -1) { } } catch (java.io.IOException closed) { }
                cancel(running, "PHONE_COMPAT_CANCELLED");
            }, "PhoneCompatCaller");
            caller.setDaemon(true); caller.start();
            RootInstaller.directory();
            try (FileChannel channel = FileChannel.open(new File(RootInstaller.STAGE, "phone-compat.lock").toPath(),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE); FileLock lock = channel.tryLock()) {
                UpdateCore.require(lock != null, "A phone integration check is already running");
                for (String name : new String[]{"ambient", "receiver-settings"}) {
                    profile.ensureActive();
                    ProcessBuilder builder = new ProcessBuilder("/system/bin/app_process", "/system/bin", "NativeConfigRepair",
                            String.valueOf(profile.packageUser), String.valueOf(info.uid), name, "ensure");
                    builder.environment().put("CLASSPATH", info.sourceDir + ":" + RootInstaller.APK);
                    java.lang.Process child;
                    synchronized (running) { child = builder.redirectErrorStream(true).start(); running.set(child); }
                    try {
                        byte[] output = UpdateCore.bounded(child.getInputStream(), 32768);
                        UpdateCore.require(child.waitFor() == 0 && new String(output, StandardCharsets.UTF_8)
                                .contains("NATIVE_PUBLISH_CALL_COMPLETED_VERIFY_SNAPSHOT_SEPARATELY"), "Native phone configuration failed");
                    } finally { child.destroyForcibly(); running.set(null); }
                }
            }
            System.out.println("PHONE_CONFIG_CHECKED"); System.exit(0);
        } catch (Throwable failed) {
            java.lang.Process child = running.get(); if (child != null) child.destroyForcibly();
            Throwable cause = failed.getCause() == null ? failed : failed.getCause();
            System.err.println("PHONE_COMPAT_FAILED " + String.valueOf(cause.getMessage()).replace('\n', ' ').replace('\r', ' ')); System.exit(1);
        }
    }
}
