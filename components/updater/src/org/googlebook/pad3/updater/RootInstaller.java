package org.googlebook.pad3.updater;

import android.content.res.AssetFileDescriptor;
import android.os.*;
import android.system.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipFile;

/** Fixed, owner-authorized root entry point; never loads downloaded executable code. */
public final class RootInstaller {
    static final String APK = "/system_ext/priv-app/Pad3Updater/Pad3Updater.apk";
    static final File STAGE = new File("/data/misc/update_engine/googlebook-pad3");
    private static UpdateEngine engine;
    private static AssetFileDescriptor payloadFd;
    private static FileChannel lockChannel;
    private static FileLock lock;
    private static int lastStatus = -1;
    private static ActiveProfile profile;

    static void emit(String state, int percent, String message) {
        System.out.println(state + " " + Math.max(0, Math.min(100, percent)) + " " + message.replace('\n', ' ').replace('\r', ' '));
        System.out.flush();
    }
    static byte[] read(File file, int limit) throws IOException {
        try (InputStream in = new FileInputStream(file)) { return UpdateCore.bounded(in, limit); }
    }
    static byte[] key() throws IOException {
        try (ZipFile apk = new ZipFile(APK); InputStream in = apk.getInputStream(apk.getEntry("assets/release-key.der"))) {
            return UpdateCore.bounded(in, 4096);
        }
    }
    static void guard(UpdateCore.Release release) throws Exception {
        NativeIdentity.requireNative();
        profile.ensureActive();
        release.validate(System.currentTimeMillis() / 1000);
        Map<String,String> properties = new HashMap<>();
        for (String name : Arrays.asList("ro.googlebook.pad3.native", "ro.googlebook.pad3.device", "ro.googlebook.pad3.base_profile",
                "ro.gsid.image_running", "ro.build.ab_update", "ro.virtual_ab.enabled", "ro.boot.slot_suffix", "ro.googlebook.pad3.release_sequence"))
            properties.put(name, SystemProperties.get(name));
        UpdateCore.guardNative(release, properties, Build.FINGERPRINT, Build.SUPPORTED_ABIS, Os.sysconf(OsConstants._SC_PAGESIZE));
    }
    static void directory() throws Exception {
        File parent = STAGE.getParentFile();
        StructStat parentStat = Os.lstat(parent.getPath());
        UpdateCore.require(parentStat.st_uid == 0 && OsConstants.S_ISDIR(parentStat.st_mode)
                && (parentStat.st_mode & 0022) == 0, "Unsafe OTA parent directory");
        if (!STAGE.exists()) Os.mkdir(STAGE.getPath(), 0700);
        StructStat stat = Os.lstat(STAGE.getPath());
        UpdateCore.require(stat.st_uid == 0 && OsConstants.S_ISDIR(stat.st_mode) && !Files.isSymbolicLink(STAGE.toPath()), "Unsafe OTA staging directory");
        Os.chmod(STAGE.getPath(), 0700);
        UpdateCore.require(SELinux.restorecon(STAGE), "Could not label root staging directory");
    }
    static void syncDirectory() throws Exception {
        FileDescriptor fd = Os.open(STAGE.getPath(), OsConstants.O_RDONLY, 0);
        try { Os.fsync(fd); } finally { Os.close(fd); }
    }
    static void atomic(File target, byte[] bytes) throws Exception {
        File partial = new File(target.getPath() + ".part");
        UpdateCore.require(!Files.isSymbolicLink(partial.toPath()) && !Files.isSymbolicLink(target.toPath()), "Unsafe staging file");
        try (FileOutputStream out = new FileOutputStream(partial)) {
            Os.chmod(partial.getPath(), 0600); out.write(bytes); out.getFD().sync();
        }
        Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        UpdateCore.require(SELinux.restorecon(target), "Could not label staging file");
        syncDirectory();
    }
    static UpdateCore.Release stage() throws Exception {
        byte[] feed = read(profile.file("selected-feed.json"), UpdateCore.FEED_LIMIT);
        byte[] signature = read(profile.file("selected-feed.json.sig"), 1024);
        UpdateCore.Release release = ManifestCodec.select(feed, signature, key(), Build.FINGERPRINT);
        UpdateCore.require(release != null, "No signed release allows this installed native build");
        guard(release);
        File source = profile.file("ota/" + release.otaHash + "/ota.zip");
        UpdateCore.require(source.length() == release.otaSize, "Missing verified downloaded OTA");
        File partial = new File(STAGE, "ota.zip.part"), target = new File(STAGE, "ota.zip");
        UpdateCore.require(!Files.isSymbolicLink(partial.toPath()) && !Files.isSymbolicLink(target.toPath()), "Unsafe root OTA file");
        UpdateCore.require(STAGE.getUsableSpace() > release.otaSize + UpdateCore.GIB, "Insufficient root staging space");
        emit("STAGING", 0, "Copying OTA into root-owned storage");
        try (InputStream in = new FileInputStream(source); FileOutputStream out = new FileOutputStream(partial)) {
            Os.chmod(partial.getPath(), 0600);
            byte[] buffer = new byte[1024 * 1024]; long done = 0;
            for (int n; (n = in.read(buffer)) != -1;) {
                UpdateCore.require(done <= release.otaSize - n, "OTA changed during root staging");
                out.write(buffer, 0, n); done += n;
            }
            out.getFD().sync();
        }
        // Verify the root-owned copy, not an app-writable path passed to update_engine.
        UpdateCore.verifyZip(partial, release);
        guard(release);
        Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        UpdateCore.require(SELinux.restorecon(target), "Could not label OTA package");
        File metadata = new File(STAGE, "payload-metadata.bin");
        byte[] prefix = new byte[UpdateCore.metadataPrefixSize(target, release)];
        try (RandomAccessFile in = new RandomAccessFile(target, "r")) { in.seek(release.offset); in.readFully(prefix); }
        atomic(metadata, prefix);
        atomic(new File(STAGE, "pending-feed.json"), feed);
        atomic(new File(STAGE, "pending-feed.json.sig"), signature);
        syncDirectory();
        return release;
    }
    static void finish(int code, String state, String message) {
        emit(state, code == 0 ? 100 : 0, message);
        try { if (engine != null) engine.unbind(); } catch (Exception ignored) { }
        try { if (payloadFd != null) payloadFd.close(); } catch (Exception ignored) { }
        try { if (lock != null) lock.release(); if (lockChannel != null) lockChannel.close(); } catch (Exception ignored) { }
        System.exit(code);
    }
    public static void main(String[] args) {
        try {
            UpdateCore.require(android.os.Process.myUid() == 0, "SukiSU root authorization is required");
            UpdateCore.require(SELinux.isSELinuxEnforced() && "u:r:ksu:s0".equals(SELinux.getContext()),
                    "Expected the authorized ksu domain with SELinux enforcing");
            UpdateCore.require(args.length == 2 && Arrays.asList("apply", "status", "preflight").contains(args[0])
                    && args[1].matches("[0-9]{1,10}"), "Unknown helper operation/UID");
            UpdateCore.require(new File(System.getenv("CLASSPATH")).getCanonicalFile().equals(new File(APK).getCanonicalFile()),
                    "Helper must run from the installed built-in APK");
            boolean apply = args[0].equals("apply");
            boolean preflight = args[0].equals("preflight");
            if (Looper.myLooper() == null) Looper.prepareMainLooper();
            NativeIdentity.requireNative();
            profile = ActiveProfile.resolve(Integer.parseInt(args[1]), apply || preflight);
            if (apply) {
                directory();
                lockChannel = FileChannel.open(new File(STAGE, "apply.lock").toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                lock = lockChannel.tryLock();
                UpdateCore.require(lock != null, "An updater transaction already owns staging");
            }
            Handler handler = new Handler(Looper.myLooper());
            AtomicBoolean initial = new AtomicBoolean(false);
            engine = new UpdateEngine();
            UpdateCore.require(engine.bind(new UpdateEngineCallback() {
                @Override public void onStatusUpdate(int status, float percent) {
                    lastStatus = status;
                    emit("ENGINE", (int)(percent * 100), "A/B engine status " + status);
                    if (!initial.compareAndSet(false, true)) return;
                    if (status == 6) { finish(preflight ? 1 : 0, "REBOOT_REQUIRED", "Verified native update awaits an owner reboot"); return; }
                    if (preflight) {
                        try {
                            UpdateCore.require(status == 0, "Native engine is not idle");
                            UpdateCore.Release release = ManifestCodec.select(read(profile.file("selected-feed.json"), UpdateCore.FEED_LIMIT),
                                    read(profile.file("selected-feed.json.sig"), 1024), key(), Build.FINGERPRINT);
                            UpdateCore.require(release != null, "No signed release allows this installed native build");
                            guard(release);
                            finish(0, "PREFLIGHT", "Native fingerprint, sequence, DSU state and A/B engine preflight passed");
                        } catch (Exception e) { finish(1, "FAILED", e.toString()); }
                        return;
                    }
                    if (!apply) { finish(0, status == 0 ? "IDLE" : "IN_PROGRESS", "A/B engine status " + status); return; }
                    if (status != 0) { finish(1, "FAILED", "Engine is busy or requires recovery; staging was not changed"); return; }
                    new Thread(() -> {
                        try {
                            UpdateCore.Release release = stage();
                            handler.post(() -> {
                                try {
                                    guard(release);
                                    UpdateCore.require(engine.verifyPayloadMetadata(new File(STAGE, "payload-metadata.bin").getPath()),
                                            "Native engine rejected signed payload metadata");
                                    payloadFd = new AssetFileDescriptor(ParcelFileDescriptor.open(new File(STAGE, "ota.zip"), ParcelFileDescriptor.MODE_READ_ONLY),
                                            release.offset, release.payloadSize);
                                    String[] properties = Arrays.copyOf(release.properties, 5);
                                    properties[4] = "SWITCH_SLOT_ON_REBOOT=1";
                                    guard(release);
                                    engine.applyPayload(payloadFd, properties);
                                    emit("APPLYING", 0, "Verified payload FD submitted to Android A/B engine");
                                } catch (Exception e) { finish(1, "FAILED", e.toString()); }
                            });
                        } catch (Exception e) { finish(1, "FAILED", e.toString()); }
                    }, "RootOtaVerify").start();
                }
                @Override public void onPayloadApplicationComplete(int errorCode) {
                    if (errorCode == 0) finish(0, lastStatus == 6 ? "REBOOT_REQUIRED" : "COMPLETE",
                            "Payload applied; refresh engine status before rebooting");
                    else finish(1, "FAILED", "Native update_engine error " + errorCode + "; active slot was not manually changed");
                }
            }, handler), "Could not bind Android UpdateEngine (service/SELinux/root policy)");
            handler.postDelayed(() -> { if (!initial.get()) finish(1, "FAILED", "No engine status callback within 15 seconds"); }, 15000);
            Looper.loop();
        } catch (Throwable e) { finish(1, "FAILED", e.toString()); }
    }
}
