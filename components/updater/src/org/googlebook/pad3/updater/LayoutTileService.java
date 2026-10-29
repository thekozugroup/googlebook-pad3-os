package org.googlebook.pad3.updater;

import android.graphics.drawable.Icon;
import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/** Window defaults only; physical tablet posture and existing tasks remain independent. */
public final class LayoutTileService extends TileService {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private boolean busy, listening, destroyed;

    @Override public void onStartListening() { super.onStartListening(); listening = true; request(false); }
    @Override public void onStopListening() { listening = false; super.onStopListening(); }
    @Override public void onClick() {
        super.onClick();
        if (isLocked()) unlockAndRun(() -> request(true));
        else request(true);
    }
    private void show(String label, String detail, int state) {
        if (!listening || destroyed) return;
        Tile tile = getQsTile();
        if (tile == null) return;
        tile.setIcon(Icon.createWithResource(this, android.R.drawable.ic_menu_view));
        tile.setLabel(label);
        tile.setSubtitle(detail);
        tile.setContentDescription(label + ". " + detail);
        tile.setState(state);
        tile.updateTile();
    }
    private void request(boolean toggle) {
        if (busy || destroyed) return;
        busy = true;
        show("Window layout", toggle ? "Switching layout…" : "Checking layout…", Tile.STATE_UNAVAILABLE);
        worker.execute(() -> {
            String label = "Root unavailable", detail = "Allow System update in SukiSU";
            int state = Tile.STATE_INACTIVE;
            java.lang.Process process = null;
            try {
                UpdateCore.require(new File(getPackageCodePath()).getCanonicalFile().equals(new File(RootInstaller.APK).getCanonicalFile()),
                        "Requires the built-in system APK");
                String command = "CLASSPATH=" + RootInstaller.APK
                        + " /system/bin/app_process /system/bin org.googlebook.pad3.updater.RootWindowMode "
                        + (toggle ? "toggle" : "status") + " " + android.os.Process.myUid();
                process = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start();
                if (!process.waitFor(25, TimeUnit.SECONDS)) throw new IOException("Root request timed out");
                String output;
                try (InputStream in = process.getInputStream()) {
                    output = new String(UpdateCore.bounded(in, 4096), StandardCharsets.UTF_8).trim();
                }
                if (process.exitValue() == 0 && (output.equals("TABLET") || output.equals("DESKTOP"))) {
                    boolean desktop = output.equals("DESKTOP");
                    label = desktop ? "Desktop layout" : "Tablet layout";
                    detail = desktop ? "New windows: freeform" : "New windows: fullscreen";
                    state = desktop ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE;
                } else if (output.startsWith("FAILED ")) {
                    label = "Layout unavailable";
                    detail = output.substring(7, Math.min(output.length(), 127));
                }
            } catch (Exception error) {
                if (!(error instanceof IOException)) {
                    label = "Layout unavailable";
                    detail = String.valueOf(error.getMessage());
                } else if ("Root request timed out".equals(error.getMessage())) detail = error.getMessage();
            } finally { if (process != null) process.destroy(); }
            String resultLabel = label, resultDetail = detail;
            int resultState = state;
            main.post(() -> { busy = false; show(resultLabel, resultDetail, resultState); });
        });
    }
    @Override public void onDestroy() {
        destroyed = true;
        worker.shutdownNow();
        main.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
