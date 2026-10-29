package org.googlebook.pad3.updater;

import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicBoolean;

public final class UpdateService extends Service {
    static final String CHECK = "check", INSTALL = "install", STATUS = "status";
    static final String CHANGED = "org.googlebook.pad3.updater.CHANGED";
    private static final String CHANNEL = "updates";
    private static final AtomicBoolean PAUSED = new AtomicBoolean();
    private final AtomicBoolean busy = new AtomicBoolean();
    private volatile String phase = "";
    private long lastProgress;
    static void pause() { PAUSED.set(true); }
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onCreate() {
        super.onCreate();
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel(CHANNEL, "System updates", NotificationManager.IMPORTANCE_LOW));
    }
    private Notification notification(String text, int percent, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Pad 3 system update").setContentText(text).setContentIntent(open)
                .setOngoing(ongoing).setOnlyAlertOnce(true).setProgress(100, Math.max(0, percent), percent < 0).build();
    }
    private void state(String message, int percent) {
        getSharedPreferences("state", MODE_PRIVATE).edit().putString("message", message).putInt("progress", Math.max(0, percent)).apply();
        getSystemService(NotificationManager.class).notify(1, notification(message, percent, busy.get()));
        sendBroadcast(new Intent(CHANGED).setPackage(getPackageName()));
    }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (!busy.compareAndSet(false, true)) return START_NOT_STICKY;
        PAUSED.set(false);
        String command = intent == null ? STATUS : intent.getAction();
        startForeground(1, notification("Starting update operation", -1, true));
        new Thread(() -> {
            PowerManager.WakeLock wake = getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Pad3Updater:work");
            wake.acquire(6 * 60 * 60 * 1000L);
            try {
                if (CHECK.equals(command)) check();
                else if (INSTALL.equals(command)) install();
                else if (STATUS.equals(command)) root("status");
                else throw new IOException("Unknown operation");
            } catch (Exception e) { state("Update stopped: " + e.getMessage(), 0); }
            finally {
                if (wake.isHeld()) wake.release();
                busy.set(false);
                SharedPreferences saved = getSharedPreferences("state", MODE_PRIVATE);
                getSystemService(NotificationManager.class).notify(1, notification(saved.getString("message", "Operation finished"), saved.getInt("progress", 0), false));
                stopForeground(STOP_FOREGROUND_DETACH); stopSelf(id);
            }
        }, "Pad3Updater").start();
        return START_NOT_STICKY;
    }
    @Override public void onTimeout(int startId, int type) { PAUSED.set(true); state("Operation timed out; refresh engine status before retrying.", 0); stopSelf(); }
    private byte[] key() throws IOException {
        try (InputStream in = getAssets().open("release-key.der")) { return UpdateCore.bounded(in, 4096); }
    }
    private byte[] saved(String name, int limit) throws IOException {
        try (InputStream in = new FileInputStream(new File(getFilesDir(), name))) { return UpdateCore.bounded(in, limit); }
    }
    private void save(String name, byte[] bytes) throws IOException {
        File saved = new File(getFilesDir(), name), partial = new File(saved.getPath() + ".part");
        try (FileOutputStream out = new FileOutputStream(partial)) { out.write(bytes); out.getFD().sync(); }
        Files.move(partial.toPath(), saved.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    private void check() throws Exception {
        state("Checking signed public release feed", -1);
        byte[] feed = UpdateCore.fetchFeed(BuildConfig.FEED), signature = UpdateCore.fetchSignature(BuildConfig.FEED);
        UpdateCore.Release newest = ManifestCodec.select(feed, signature, key(), Build.FINGERPRINT);
        if (newest == null) {
            Files.deleteIfExists(new File(getFilesDir(), "selected-feed.json").toPath());
            Files.deleteIfExists(new File(getFilesDir(), "selected-feed.json.sig").toPath());
            state("No published signed release allows this installed build.", 0);
        } else {
            save("selected-feed.json", feed); save("selected-feed.json.sig", signature);
            state("Available: " + newest.version + " · " + (newest.otaSize / (1024 * 1024)) + " MiB. Tap Download and install.", 0);
        }
    }
    private void progress(long done, long total) throws IOException {
        UpdateCore.require(!PAUSED.get(), "Download paused; tap Download and install to resume");
        long now = SystemClock.elapsedRealtime();
        if (now - lastProgress > 400 || done == total) { state(phase, (int)(100 * done / total)); lastProgress = now; }
    }
    private void install() throws Exception {
        UpdateCore.require(BuildConfig.KEY_PROVISIONED, "Parent must rebuild with the release public key");
        UpdateCore.Release release = ManifestCodec.select(saved("selected-feed.json", UpdateCore.FEED_LIMIT),
                saved("selected-feed.json.sig", 1024), key(), Build.FINGERPRINT);
        UpdateCore.require(release != null, "No signed release allows this installed build");
        UpdateCore.require(release.fingerprints.contains(Build.FINGERPRINT), "Release does not allow this installed build");
        state("Checking authorized native base before downloading", -1);
        root("preflight");
        File directory = new File(new File(getFilesDir(), "ota"), release.otaHash);
        Files.createDirectories(directory.toPath());
        File existing = new File(directory, "ota.zip");
        if (!existing.isFile()) {
            UpdateCore.require(directory.getUsableSpace() > 2 * release.otaSize + UpdateCore.GIB, "Need space for parts, joined OTA and staging");
            for (int i = 0; i < release.parts.size(); i++) {
                phase = "Downloading verified part " + (i + 1) + "/" + release.parts.size();
                UpdateCore.download(release.parts.get(i), new File(directory, "part-" + i), this::progress);
            }
        }
        phase = "Verifying and joining OTA parts";
        File ota = UpdateCore.join(release, directory, this::progress);
        state("Verifying stored payload and signed metadata", -1);
        UpdateCore.verifyZip(ota, release);
        UpdateCore.require(!PAUSED.get(), "Paused before installation");
        state("Requesting owner-authorized SukiSU root for native A/B installation", -1);
        root("apply");
    }
    private void root(String operation) throws Exception {
        UpdateCore.require(new File(getPackageCodePath()).getCanonicalFile().equals(new File(RootInstaller.APK).getCanonicalFile()),
                "Apply/status requires the built-in system APK at the integration path");
        String command = "CLASSPATH=" + RootInstaller.APK + " /system/bin/app_process /system/bin org.googlebook.pad3.updater.RootInstaller "
                + operation + " " + android.os.Process.myUid();
        java.lang.Process process;
        try {
            process = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start();
        } catch (IOException unavailable) {
            throw new IOException("Open SukiSU's Superuser page, enable Show system apps, and allow System update. Then retry.", unavailable);
        }
        String last = "Root authorization was denied or helper could not start";
        try (BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] values = line.split(" ", 3);
                if (values.length == 3 && values[1].matches("[0-9]{1,3}")) { last = values[2]; state(last, Integer.parseInt(values[1])); }
            }
        }
        UpdateCore.require(process.waitFor() == 0, last + "; refresh engine status before retrying");
    }
}
