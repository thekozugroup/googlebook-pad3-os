package org.googlebook.pad3.updater;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.Process;
import android.os.UserManager;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.io.IOException;

/** One bounded reconciliation after unlock or a relevant package replacement. */
public final class PhoneCompatibilityJob extends JobService {
    private static final int ID = 0x50443301;
    private volatile Run active;
    static final class Run {
        boolean cancelled;
        java.lang.Process child;
        synchronized java.lang.Process start(ProcessBuilder builder) throws IOException {
            if (cancelled) throw new IOException("Phone check cancelled");
            child = builder.start(); return child;
        }
        synchronized void cancel() {
            cancelled = true;
            if (child != null) {
                try { child.getOutputStream().close(); } catch (IOException ignored) { }
                child.destroyForcibly();
            }
        }
    }

    static void schedule(Context context) {
        if (Process.myUid() / 100000 == 0 || !context.getSystemService(UserManager.class).isUserUnlocked()) return;
        JobScheduler jobs = context.getSystemService(JobScheduler.class);
        if (jobs.getPendingJob(ID) != null) return;
        jobs.schedule(new JobInfo.Builder(ID, new ComponentName(context, PhoneCompatibilityJob.class))
                .setMinimumLatency(5000).setOverrideDeadline(30000).build());
    }
    @Override public boolean onStartJob(JobParameters parameters) {
        Run execution = new Run();
        active = execution;
        new Thread(() -> {
            boolean passed = false;
            java.lang.Process child = null;
            try {
                if (!getSystemService(UserManager.class).isUserUnlocked()) throw new IllegalStateException("User locked");
                String command = "CLASSPATH=" + RootInstaller.APK + " /system/bin/app_process /system/bin "
                        + "org.googlebook.pad3.updater.RootPhoneCompatibility " + Process.myUid();
                child = execution.start(new ProcessBuilder("su", "-c", command).redirectErrorStream(true));
                UpdateCore.require(child.waitFor(95, TimeUnit.SECONDS), "Root authorization or maintenance timed out");
                String output = new String(UpdateCore.bounded(child.getInputStream(), 16384), StandardCharsets.UTF_8);
                passed = RootPhoneCompatibility.configurationChecked(child.exitValue(), output);
            } catch (Exception failed) {
                Log.w("Pad3PhoneCompat", "Phone integration check could not complete");
            } finally {
                if (child != null) {
                    try { child.getOutputStream().close(); } catch (IOException ignored) { }
                    child.destroyForcibly();
                }
                synchronized (execution) {
                    if (!execution.cancelled) {
                        getSharedPreferences("phone-compat", MODE_PRIVATE).edit().putBoolean("configuration_checked", passed)
                                .putLong("checked_at", System.currentTimeMillis()).putString("build", android.os.Build.FINGERPRINT).apply();
                        Log.i("Pad3PhoneCompat", passed ? "Phone configuration checked" : "Phone configuration needs review");
                        jobFinished(parameters, false);
                    }
                }
            }
        }, "Pad3PhoneCompat").start();
        return true;
    }
    @Override public boolean onStopJob(JobParameters parameters) {
        Run execution = active;
        if (execution != null) execution.cancel();
        return false;
    }
}
