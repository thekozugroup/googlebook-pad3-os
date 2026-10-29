package org.googlebook.pad3.updater;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

public final class MainActivity extends Activity {
    private TextView status;
    private ProgressBar progress;
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) { refresh(); }
    };
    private void command(String action) { startForegroundService(new Intent(this, UpdateService.class).setAction(action)); }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL);
        int padding = (int)(24 * getResources().getDisplayMetrics().density); body.setPadding(padding, padding, padding, padding);
        body.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
            view.setPadding(padding + bars.left, padding + bars.top, padding + bars.right, padding + bars.bottom);
            return insets;
        });
        TextView title = new TextView(this); title.setText("System update"); title.setTextSize(28); body.addView(title);
        TextView details = new TextView(this);
        details.setText("OnePlus Pad 3 · GoogleBook OS\nSigned releases from thekozugroup/googlebook-pad3-os\nNative A/B updates require your SukiSU authorization."
                + (BuildConfig.KEY_PROVISIONED ? "" : "\nRelease verification key is not provisioned; installation is disabled."));
        body.addView(details);
        status = new TextView(this); status.setTextSize(18); status.setPadding(0, padding, 0, padding); body.addView(status);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setMax(100); body.addView(progress);
        button(body, "Check for updates", v -> command(UpdateService.CHECK));
        button(body, "Download and install", v -> new AlertDialog.Builder(this).setTitle("Install a native system update?")
                .setMessage("Only a signed release matching this installed native build can be applied. The update writes the inactive A/B slot. Keep the tablet charged and review the result before rebooting.")
                .setNegativeButton("Cancel", null).setPositiveButton("Continue", (d, w) -> command(UpdateService.INSTALL)).show());
        button(body, "Pause download", v -> UpdateService.pause());
        button(body, "Refresh install status", v -> command(UpdateService.STATUS));
        ScrollView scroll = new ScrollView(this); scroll.addView(body); setContentView(scroll);
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
    }
    private void button(LinearLayout body, String text, View.OnClickListener listener) {
        Button button = new Button(this); button.setText(text); button.setOnClickListener(listener); body.addView(button);
    }
    private void refresh() {
        android.content.SharedPreferences state = getSharedPreferences("state", MODE_PRIVATE);
        status.setText(state.getString("message", "Check for a published, signed update."));
        progress.setProgress(state.getInt("progress", 0));
    }
    @Override public void onResume() { super.onResume(); registerReceiver(receiver, new IntentFilter(UpdateService.CHANGED), RECEIVER_NOT_EXPORTED); refresh(); }
    @Override public void onPause() { unregisterReceiver(receiver); super.onPause(); }
}
