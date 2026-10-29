package org.googlebook.pad3.updater;

import android.os.IBinder;
import android.os.SystemProperties;
import android.system.Os;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** No userdata writes: both protected Binder state and mounted kernel identity must prove native boot. */
final class NativeIdentity {
    static boolean query(String serviceName, String interfaceName, String method) throws Exception {
        IBinder binder = (IBinder)Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, serviceName);
        UpdateCore.require(binder != null, "Protected boot-state service is unavailable: " + serviceName);
        Class<?> api = Class.forName(interfaceName);
        Object service = Class.forName(interfaceName + "$Stub").getMethod("asInterface", IBinder.class).invoke(null, binder);
        UpdateCore.require(service != null, "Protected boot-state interface is unavailable");
        Object result = api.getMethod(method).invoke(service);
        UpdateCore.require(result instanceof Boolean, "Protected boot-state response is invalid");
        return (Boolean)result;
    }
    static void requireNative() throws Exception {
        String slot = SystemProperties.get("ro.boot.slot_suffix");
        long dev = Os.stat("/system").st_dev;
        // Bionic sys/sysmacros.h encoding; SDK Os has no public major()/minor() helpers.
        String path = "/sys/dev/block/" + UpdateCore.deviceMajor(dev) + ":" + UpdateCore.deviceMinor(dev) + "/dm/name";
        String name;
        try (InputStream in = new FileInputStream(path)) {
            name = new String(UpdateCore.bounded(in, 128), StandardCharsets.UTF_8).trim();
        }
        UpdateCore.guardSystemDm(name, slot); // Reject guest/overlay mounts before touching app data or staging.
        boolean dynamic = query("dynamic_system", "android.os.image.IDynamicSystemService", "isInUse");
        boolean gsi = query("gsiservice", "android.gsi.IGsiService", "isGsiRunning");
        UpdateCore.guardNativeBoot(dynamic, gsi, name, slot);
    }
}
