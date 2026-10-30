package com.android.internal.util.googlebook;

import android.os.Build;
import android.util.Log;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;

/** Photos-only device compatibility, called by the framework after process binding. */
public final class PhotosCompat {
    private static final String PACKAGE = "com.google.android.apps.photos";
    private static final String TAG = "Pad3PhotosCompat";
    private static volatile boolean active;

    private PhotosCompat() {}

    public static synchronized void onBind(String packageName) {
        if (active || !PACKAGE.equals(packageName)) return;
        Map<String, String> previous = new LinkedHashMap<>();
        try {
            String boundPackage = (String) Class.forName("android.app.ActivityThread")
                    .getDeclaredMethod("currentPackageName").invoke(null);
            if (!PACKAGE.equals(boundPackage)) return;
            for (Map.Entry<String, String> entry : profile().entrySet()) {
                Field field = Build.class.getDeclaredField(entry.getKey());
                field.setAccessible(true);
                previous.put(entry.getKey(), (String) field.get(null));
                write(field, entry.getValue());
            }
            active = true;
            Log.i(TAG, "Photos-only Pixel XL compatibility active; Android version and security patch unchanged");
        } catch (Throwable failure) {
            for (Map.Entry<String, String> entry : previous.entrySet()) {
                try {
                    Field field = Build.class.getDeclaredField(entry.getKey());
                    field.setAccessible(true);
                    write(field, entry.getValue());
                } catch (Throwable rollback) { failure.addSuppressed(rollback); }
            }
            Log.e(TAG, "Photos compatibility could not be applied", failure);
        }
    }

    static Map<String, String> profile() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("BRAND", "google");
        fields.put("MANUFACTURER", "Google");
        fields.put("DEVICE", "marlin");
        fields.put("PRODUCT", "marlin");
        fields.put("HARDWARE", "marlin");
        fields.put("ID", "QP1A.191005.007.A3");
        fields.put("MODEL", "Pixel XL");
        fields.put("FINGERPRINT", "google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys");
        return fields;
    }

    private static void write(Field field, String value) throws Exception {
        if (value == null ? field.get(null) == null : value.equals(field.get(null))) return;
        try {
            field.set(null, value);
        } catch (IllegalAccessException finalField) {
            // ART 17 rejects reflective writes to final Build fields even for framework callers.
            Class<?> type = Class.forName("sun.misc.Unsafe");
            Object unsafe = null;
            for (String name : new String[]{"theUnsafe", "THE_ONE"}) {
                try {
                    Field instance = type.getDeclaredField(name);
                    instance.setAccessible(true);
                    unsafe = instance.get(null);
                    if (unsafe != null) break;
                } catch (NoSuchFieldException absent) { /* Android runtimes use different singleton names. */ }
            }
            if (unsafe == null) throw finalField;
            Field offset = Field.class.getDeclaredField("offset");
            offset.setAccessible(true);
            type.getMethod("putObject", Object.class, long.class, Object.class)
                    .invoke(unsafe, field.getDeclaringClass(), offset.getLong(field), value);
        }
        if (!(value == null ? field.get(null) == null : value.equals(field.get(null))))
            throw new IllegalStateException("Build write did not persist: " + field.getName());
    }

    public static Boolean feature(String name, int version) {
        if (!active || name == null) return null;
        if (name.equals("com.google.android.apps.photos.NEXUS_PRELOAD")
                || name.equals("com.google.android.apps.photos.nexus_preload")) return Boolean.TRUE;
        if (name.startsWith("com.google.android.apps.photos.PIXEL_") && name.endsWith("_PRELOAD")
                || name.startsWith("com.google.android.feature.PIXEL_")
                || name.equals("com.google.android.feature.GOOGLE_BUILD")
                || name.equals("com.google.android.feature.GOOGLE_EXPERIENCE")) return Boolean.FALSE;
        return null;
    }
}
