package org.googlebook.pad3.diagnostics;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.icu.util.MeasureUnit;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.HardwarePropertiesManager;
import android.os.Process;
import android.util.Log;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedInterface.HookHandle;
import io.github.libxposed.api.XposedInterface.Hooker;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;

/** Adapts only the exact audited Google Diagnostics APK, inside its own process. */
public final class DiagnosticsModule extends XposedModule {
    private static final String TAG = "Pad3Diagnostics", BASE = "com.google.android.factory.diagnostics.";
    private final Map<Object, MetricValues.CpuHistory> histories = Collections.synchronizedMap(new WeakHashMap<>());
    private volatile boolean installed, temperatureMissing = true, healthMissing = true, wifiMissing;
    private boolean memoryLogged;
    private final List<HookHandle> handles = new ArrayList<>();

    private void install(Executable target, Hooker interceptor) {
        handles.add(hook(target).intercept(interceptor));
    }

    private static Field field(Class<?> type, String name) throws Exception {
        Field value = type.getDeclaredField(name); value.setAccessible(true); return value;
    }

    private static Method named(Class<?> type, String name, int parameters) throws Exception {
        Method selected = null;
        for (Method value : type.getDeclaredMethods()) if (value.getName().equals(name)
                && value.getParameterCount() == parameters) {
            if (selected != null) throw new NoSuchMethodException("Ambiguous " + name);
            selected = value;
        }
        if (selected == null) throw new NoSuchMethodException(name);
        selected.setAccessible(true); return selected;
    }

    private static Application application() throws Exception {
        Method current = Class.forName("android.app.ActivityThread").getDeclaredMethod("currentApplication");
        current.setAccessible(true); return (Application) current.invoke(null);
    }

    private static String digest(String file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream stream = Files.newInputStream(Paths.get(file))) {
            byte[] buffer = new byte[32768]; int count;
            while ((count = stream.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) hex.append(String.format(Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }

    private static int gaugeHealth() throws Exception {
        try (InputStream stream = Files.newInputStream(Paths.get("/sys/devices/virtual/oplus_chg/battery/battery_soh"))) {
            byte[] data = new byte[17]; int count = stream.read(data);
            if (count <= 0 || count == data.length) throw new IllegalArgumentException("Invalid health record");
            return MetricValues.health(new String(data, 0, count, StandardCharsets.US_ASCII));
        }
    }

    private static boolean label(String text, String resource) {
        try {
            Application app = application();
            int id = app.getResources().getIdentifier(resource, "string", MetricValues.TARGET);
            return id != 0 && text.equals(app.getString(id));
        } catch (Exception unavailable) { return false; }
    }

    @Override public synchronized void onPackageReady(PackageReadyParam param) {
        if (installed || !MetricValues.TARGET.equals(param.getPackageName())
                || Process.myUid() % 100000 != 1000) return;
        try {
            ApplicationInfo info = param.getApplicationInfo();
            if (info.uid != Process.myUid() || !MetricValues.allowed(param.getPackageName(), info.uid, digest(info.sourceDir))) {
                log(Log.WARN, TAG, "Unsupported Diagnostics APK; adapter not applied"); return;
            }
            ClassLoader loader = param.getClassLoader();
            Class<?> wifi = loader.loadClass(BASE + "datasource.WifiNetworkState");
            Class<?> memory = loader.loadClass(BASE + "viewmodel.memory.MemoryState");
            Class<?> cpu = loader.loadClass(BASE + "viewmodel.cpu.CpuViewModel");
            Class<?> state = loader.loadClass(BASE + "viewmodel.cpu.CpuState");
            Class<?> chart = loader.loadClass(BASE + "viewmodel.common.LineChartState");
            Method update = cpu.getDeclaredMethod("updateUsageDataLists", long.class, long.class, long.class, state);
            Method chartCopy = chart.getDeclaredMethod("copy$default", chart, int.class, int.class,
                    List.class, long.class, int.class, Object.class);
            Method memoryFormat = named(loader.loadClass(BASE + "utils.SizeUtilsKt"), "toFormattedByteString", 4);
            Method cell = named(loader.loadClass(BASE + "ui.common.PageKt"), "InformationCell", 6);
            Method strings = named(loader.loadClass("androidx.compose.ui.res.StringResources_androidKt"), "stringResource", 4);
            // Resolve every private target before installing hooks; input drift leaves the app untouched.
            Constructor<?> memoryCtor = memory.getDeclaredConstructor(long.class, long.class);
            Constructor<?> wifiCtor = wifi.getDeclaredConstructor(android.net.LinkProperties.class, WifiManager.class, WifiInfo.class);
            Method wifiChannel = wifi.getDeclaredMethod("getWifiChannel", int.class);
            Method getFlow = loader.loadClass("kotlinx.coroutines.flow.StateFlow").getMethod("getValue");
            Method setFlow = loader.loadClass("kotlinx.coroutines.flow.MutableStateFlow").getMethod("setValue", Object.class);
            Method userUsage = state.getMethod("setUserUsage", int.class), systemUsage = state.getMethod("setSystemUsage", int.class),
                    totalUsage = state.getMethod("setTotalUsage", int.class);
            Field chartFlow = field(cpu, "_lineChartState"), currentUser = field(cpu, "_currentUsers"),
                    currentSystem = field(cpu, "_currentSystem"), currentTotal = field(cpu, "_currentTotal");

            install(BatteryManager.class.getDeclaredMethod("getIntProperty", int.class), chain -> {
                int original = (Integer) chain.proceed();
                if ((Integer) chain.getArg(0) != 10) return original;
                if (original > 0 && original <= 100) { healthMissing = false; return original; }
                try { int value = gaugeHealth(); healthMissing = false; return value; }
                catch (Exception unavailable) { healthMissing = true; return Integer.MIN_VALUE; }
            });
            install(HardwarePropertiesManager.class.getDeclaredMethod("getDeviceTemperatures", int.class, int.class), chain -> {
                float[] values = (float[]) chain.proceed();
                if ((Integer) chain.getArg(0) == HardwarePropertiesManager.DEVICE_TEMPERATURE_CPU
                        && (Integer) chain.getArg(1) == HardwarePropertiesManager.TEMPERATURE_CURRENT) {
                    temperatureMissing = values == null;
                    if (values != null) { temperatureMissing = true;
                        for (float value : values) if (Float.isFinite(value)
                                && value != HardwarePropertiesManager.UNDEFINED_TEMPERATURE) temperatureMissing = false;
                    }
                }
                return values;
            });
            install(wifiChannel, chain -> ScanResult.convertFrequencyMhzToChannelIfSupported((Integer) chain.getArg(0)));
            install(wifiCtor, chain -> {
                Object[] args = chain.getArgs().toArray();
                if (args[2] == null) {
                    try {
                        ConnectivityManager manager = (ConnectivityManager) application().getSystemService(Context.CONNECTIVITY_SERVICE);
                        NetworkCapabilities capabilities = manager.getNetworkCapabilities(manager.getActiveNetwork());
                        if (capabilities != null && capabilities.getTransportInfo() instanceof WifiInfo)
                            args[2] = capabilities.getTransportInfo();
                    } catch (Exception unavailable) { /* Details remain explicitly unavailable. */ }
                }
                wifiMissing = args[2] == null;
                Object result = chain.proceed(args);
                if (wifiMissing) {
                    field(wifi, "signalStrength").setInt(chain.getThisObject(), Integer.MIN_VALUE);
                    field(wifi, "signalStrengthLevel").setInt(chain.getThisObject(), 0);
                }
                return result;
            });
            install(memoryCtor, chain -> {
                ActivityManager.MemoryInfo actual = new ActivityManager.MemoryInfo();
                ActivityManager manager = (ActivityManager) application().getSystemService(Context.ACTIVITY_SERVICE);
                manager.getMemoryInfo(actual);
                long[] values = MetricValues.memory(actual.totalMem, actual.availMem);
                if (!memoryLogged) { memoryLogged = true;
                    log(Log.INFO, TAG, "RAM: totalBytes=" + actual.totalMem + ", availableBytes=" + actual.availMem);
                }
                return chain.proceed(new Object[]{values[0], values[1]});
            });
            install(memoryFormat, chain -> {
                List<MeasureUnit> units = Arrays.asList(MeasureUnit.BYTE, MeasureUnit.KILOBYTE,
                        MeasureUnit.MEGABYTE, MeasureUnit.GIGABYTE, MeasureUnit.TERABYTE);
                int index = units.indexOf(chain.getArg(1));
                return index < 0 ? chain.proceed() : MetricValues.bytes((Number) chain.getArg(0), index,
                        (Integer) chain.getArg(2), (Integer) chain.getArg(3), Locale.getDefault());
            });
            install(update, chain -> {
                Object model = chain.getThisObject(), value = chain.getArg(3);
                long users = (Long) chain.getArg(0), system = (Long) chain.getArg(1), total = (Long) chain.getArg(2);
                MetricValues.CpuHistory history;
                synchronized (histories) { history = histories.get(model);
                    if (history == null) { history = new MetricValues.CpuHistory(); histories.put(model, history); }
                }
                int[] measured = history.sample(users, system, total);
                userUsage.invoke(value, measured == null ? Integer.MIN_VALUE : measured[0]);
                systemUsage.invoke(value, measured == null ? Integer.MIN_VALUE : measured[1]);
                totalUsage.invoke(value, measured == null ? Integer.MIN_VALUE : measured[2]);
                Object flow = chartFlow.get(model), old = getFlow.invoke(flow);
                setFlow.invoke(flow, chartCopy.invoke(null, old, 0, 0, history.series(), 0L, 11, null));
                currentUser.setLong(model, users); currentSystem.setLong(model, system); currentTotal.setLong(model, total);
                return null;
            });
            install(cell, chain -> {
                String title = (String) chain.getArg(0), text = (String) chain.getArg(1);
                boolean missing = text.contains(Integer.toString(Integer.MIN_VALUE))
                        || temperatureMissing && label(title, "cpu_temperature_label")
                        || healthMissing && label(title, "battery_health_label")
                        || wifiMissing && (label(title, "channel_label") || label(title, "signal_strength_label"));
                if (!missing) return chain.proceed();
                Object[] args = chain.getArgs().toArray(); args[1] = MetricValues.UNAVAILABLE;
                return chain.proceed(args);
            });
            install(strings, chain -> {
                String result = (String) chain.proceed();
                result = result.replace(Integer.MIN_VALUE + " %", MetricValues.UNAVAILABLE)
                        .replace(Integer.toString(Integer.MIN_VALUE), MetricValues.UNAVAILABLE);
                if ((Integer) chain.getArg(0) == 0x7f110024) {
                    Object[] args = (Object[]) chain.getArg(1);
                    if (args.length == 1 && args[0] instanceof Number && ((Number) args[0]).longValue() <= 0)
                        return MetricValues.UNAVAILABLE;
                }
                return result;
            });
            for (String name : new String[]{"viewmodel.memory.MemoryViewModel", "viewmodel.cpu.CpuViewModel"})
                deoptimize(named(loader.loadClass(BASE + name), "refresh", 1));
            deoptimize(wifiCtor);
            installed = true;
            log(Log.INFO, TAG, "Audited Diagnostics metrics adapter active; target hash verified");
        } catch (Throwable error) {
            for (int i = handles.size() - 1; i >= 0; i--) {
                try { handles.get(i).unhook(); }
                catch (Throwable rollback) { log(Log.ERROR, TAG, "Hook rollback failed", rollback); }
            }
            handles.clear();
            log(Log.ERROR, TAG, "Diagnostics adapter failed; runtime verification required", error);
        }
    }
}
