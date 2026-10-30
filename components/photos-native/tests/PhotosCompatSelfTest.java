package com.android.internal.util.googlebook;

import java.lang.reflect.Field;
import java.util.Map;

public final class PhotosCompatSelfTest {
    private static int checks;
    private static void check(boolean value) { checks++; if (!value) throw new AssertionError(checks); }

    public static void main(String[] args) throws Exception {
        PhotosCompat.onBind(null);
        PhotosCompat.onBind("com.google.android.gms");
        PhotosCompat.onBind("com.google.android.apps.photos.other");
        check(PhotosCompat.feature("com.google.android.apps.photos.NEXUS_PRELOAD", 0) == null);
        Map<String, String> fields = PhotosCompat.profile();
        check(fields.size() == 8 && fields.get("MODEL").equals("Pixel XL"));
        check(fields.get("DEVICE").equals("marlin") && fields.get("HARDWARE").equals("marlin"));
        check(!fields.containsKey("SDK_INT") && !fields.containsKey("SECURITY_PATCH")
                && !fields.containsKey("RELEASE") && !fields.containsKey("SUPPORTED_ABIS"));
        Field active = PhotosCompat.class.getDeclaredField("active");
        active.setAccessible(true);
        active.setBoolean(null, true);
        check(PhotosCompat.feature(null, 0) == null);
        check(Boolean.TRUE.equals(PhotosCompat.feature("com.google.android.apps.photos.NEXUS_PRELOAD", 0)));
        check(Boolean.TRUE.equals(PhotosCompat.feature("com.google.android.apps.photos.nexus_preload", 0)));
        for (String flag : new String[]{"com.google.android.apps.photos.PIXEL_2019_PRELOAD",
                "com.google.android.feature.PIXEL_2026_EXPERIENCE", "com.google.android.feature.PIXEL_EXPERIENCE",
                "com.google.android.feature.GOOGLE_BUILD", "com.google.android.feature.GOOGLE_EXPERIENCE"})
            check(Boolean.FALSE.equals(PhotosCompat.feature(flag, 0)));
        for (String flag : new String[]{"android.hardware.camera", "android.hardware.camera.front",
                "android.hardware.touchscreen", "android.hardware.sensor.accelerometer",
                "android.software.game_service", "com.google.photos.trust_debug_certs", "unknown"})
            check(PhotosCompat.feature(flag, 0) == null);
        active.setBoolean(null, false);
        check(PhotosCompat.feature("com.google.android.apps.photos.NEXUS_PRELOAD", 0) == null);
        System.out.println(checks + " Photos framework scope/profile checks passed; ART final-field writes require the device probe");
    }
}
