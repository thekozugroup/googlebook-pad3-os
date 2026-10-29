package vendor.google.libraries.desktop.serviceability;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Debug;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.CpuUsageInfo;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.CpuUsageInfoWithProcessUsage;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.LogicalCpuInfo;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.PhysicalCpuInfo;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.ProcessCpuUsageInfo;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.ProcessMemoryUsageInfo;

/** Read-only fallback for the audited Task Manager, under its existing process identity. */
final class TaskManagerCompat {
    static final String PACKAGE = "com.google.android.factory.taskmanager";
    private static final Path PROC = Paths.get("/proc");
    private static final Path CPU = Paths.get("/sys/devices/system/cpu");

    interface MissingService {
        boolean missing();
    }

    interface LivePid {
        boolean exists(int pid);
    }

    private static ActivityManager activityManager(Context context) {
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (manager == null) throw new IllegalStateException("ActivityManager unavailable");
        return manager;
    }

    private static LivePid livePids(final ActivityManager manager) {
        return new LivePid() {
            @Override public boolean exists(int pid) {
                List<ActivityManager.RunningAppProcessInfo> processes = manager.getRunningAppProcesses();
                if (processes == null) throw new IllegalStateException("Process liveness unavailable");
                for (ActivityManager.RunningAppProcessInfo process : processes) {
                    if (process.pid == pid) return true;
                }
                return false;
            }
        };
    }

    static boolean selectMode(String packageName, int uid, int contextUid, MissingService lookup) {
        if (!PACKAGE.equals(packageName) || uid < 0 || uid % 100000 != 1000 || contextUid != uid) {
            return false;
        }
        return lookup.missing();
    }

    static boolean shouldUse(Context context) {
        if (!PACKAGE.equals(context.getPackageName())) return false;
        Context application = context.getApplicationContext();
        final Context app = application == null ? context : application;
        return selectMode(app.getPackageName(), Process.myUid(), app.getApplicationInfo().uid,
                new MissingService() {
                    @Override public boolean missing() {
                        try {
                            // Include disabled/uninstalled components: those states are not absence.
                            app.getPackageManager().getServiceInfo(new ComponentName(
                                    "vendor.google.desktop.serviceability",
                                    "vendor.google.desktop.serviceability.VendorServiceabilityService"),
                                    PackageManager.MATCH_DISABLED_COMPONENTS
                                    | PackageManager.MATCH_UNINSTALLED_PACKAGES
                                    | PackageManager.MATCH_DIRECT_BOOT_AWARE
                                    | PackageManager.MATCH_DIRECT_BOOT_UNAWARE);
                            return false;
                        } catch (PackageManager.NameNotFoundException absent) {
                            return true;
                        }
                    }
                });
    }

    private static long hz() {
        long value = Os.sysconf(OsConstants._SC_CLK_TCK);
        if (value <= 0) throw new IllegalStateException("USER_HZ unavailable");
        return value;
    }

    private static String read(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        if (data.length > 131072) throw new IOException("Metric file too large: " + path);
        return new String(data, StandardCharsets.UTF_8).trim();
    }

    private static long number(String text) {
        long value = Long.parseLong(text);
        if (value < 0) throw new IllegalArgumentException("Negative metric counter");
        return value;
    }

    static long ticks(long value, long hz) {
        if (value < 0 || hz <= 0) throw new IllegalArgumentException("Invalid CPU tick value/unit");
        return hz == 100 ? value : Math.multiplyExact(value, 100) / hz;
    }

    static CpuUsageInfo parseCpu(String text, long hz) {
        String[] fields = text.split("\\R", 2)[0].trim().split("\\s+");
        if (fields.length < 9 || !fields[0].equals("cpu")) {
            throw new IllegalArgumentException("Missing aggregate CPU counters");
        }
        long[] raw = new long[8];
        long total = 0;
        for (int i = 0; i < raw.length; i++) {
            raw[i] = number(fields[i + 1]);
            total = Math.addExact(total, raw[i]);
        }
        long user = Math.addExact(raw[0], raw[1]);
        long system = Math.addExact(Math.addExact(raw[2], raw[5]), raw[6]);
        return new CpuUsageInfo(ticks(user, hz), ticks(system, hz), ticks(total, hz));
    }

    static CpuUsageInfo cpu() {
        try {
            return parseCpu(read(PROC.resolve("stat")), hz());
        } catch (IOException failure) {
            throw unavailable("aggregate CPU", failure);
        }
    }

    static final class ProcStat {
        final int pid;
        final long user;
        final long system;
        final long start;

        ProcStat(int pid, long user, long system, long start) {
            this.pid = pid;
            this.user = user;
            this.system = system;
            this.start = start;
        }
    }

    static ProcStat parseProcess(int pid, String text) {
        if (pid <= 0) throw new IllegalArgumentException("Invalid PID");
        int open = text.indexOf('(');
        int close = text.lastIndexOf(')');
        if (open < 1 || close <= open || Integer.parseInt(text.substring(0, open).trim()) != pid) {
            throw new IllegalArgumentException("Invalid PID stat header");
        }
        String[] fields = text.substring(close + 1).trim().split("\\s+");
        if (fields.length < 20 || fields[0].length() != 1) {
            throw new IllegalArgumentException("Incomplete PID stat");
        }
        return new ProcStat(pid, number(fields[11]), number(fields[12]), number(fields[19]));
    }

    private static void validatePids(int[] pids) {
        if (pids == null) throw new NullPointerException("pids");
        for (int pid : pids) if (pid <= 0) throw new IllegalArgumentException("Invalid PID");
    }

    static ProcStat process(Path proc, int pid) throws IOException {
        return parseProcess(pid, read(proc.resolve(Integer.toString(pid)).resolve("stat")));
    }

    static CpuUsageInfoWithProcessUsage processCpu(Path proc, int[] pids, long hz, LivePid live) throws IOException {
        validatePids(pids);
        CpuUsageInfo total = parseCpu(read(proc.resolve("stat")), hz);
        List<ProcessCpuUsageInfo> samples = new ArrayList<>();
        for (int pid : pids) {
            try {
                ProcStat stat = process(proc, pid);
                samples.add(new ProcessCpuUsageInfo(pid, ticks(stat.user, hz), ticks(stat.system, hz)));
            } catch (NoSuchFileException exited) {
                if (live.exists(pid)) {
                    throw new IllegalStateException("CPU stat inaccessible for live PID " + pid, exited);
                }
                // A process can exit after ActivityManager enumerates it; do not invent counters.
            }
        }
        return new CpuUsageInfoWithProcessUsage(total.userTotalCpuUsage, total.systemTotalCpuUsage,
                total.totalCpuUsage, Collections.unmodifiableList(samples));
    }

    static CpuUsageInfoWithProcessUsage cpuWithProcesses(Context context, int[] pids) {
        try {
            return processCpu(PROC, pids, hz(), livePids(activityManager(context)));
        } catch (IOException failure) {
            throw unavailable("process CPU", failure);
        }
    }

    static TreeSet<Integer> cpuIds(String text) {
        TreeSet<Integer> result = new TreeSet<>();
        for (String item : text.trim().split(",", -1)) {
            String[] range = item.trim().split("-", -1);
            if (range.length > 2) throw new IllegalArgumentException("Invalid CPU range");
            int first = Integer.parseInt(range[0]);
            int last = range.length == 1 ? first : Integer.parseInt(range[1]);
            if (first < 0 || last < first || last >= 4096) {
                throw new IllegalArgumentException("Invalid CPU ID/range");
            }
            for (int cpu = first; cpu <= last; cpu++) {
                if (!result.add(cpu)) throw new IllegalArgumentException("Repeated CPU ID");
            }
        }
        if (result.isEmpty()) throw new IllegalArgumentException("Empty CPU topology");
        return result;
    }

    private static int frequency(Path path) throws IOException {
        long value = number(read(path));
        if (value == 0 || value > Integer.MAX_VALUE) {
            throw new IllegalStateException("Frequency unavailable: " + path);
        }
        return (int) value;
    }

    static List<PhysicalCpuInfo> topology(Path root) throws IOException {
        TreeSet<Integer> present = cpuIds(read(root.resolve("present")));
        TreeSet<Integer> online = cpuIds(read(root.resolve("online")));
        if (!present.containsAll(online)) throw new IllegalStateException("Inconsistent CPU topology");
        Map<Integer, List<LogicalCpuInfo>> packages = new TreeMap<>();
        for (int id : present) {
            Path cpu = root.resolve("cpu" + id);
            int packageId = Integer.parseInt(read(cpu.resolve("topology/physical_package_id")));
            int current = 0;
            if (online.contains(id)) {
                try {
                    current = frequency(cpu.resolve("cpufreq/scaling_cur_freq"));
                } catch (NoSuchFileException notExported) {
                    current = frequency(cpu.resolve("cpufreq/cpuinfo_cur_freq"));
                }
            }
            int maximum = frequency(cpu.resolve("cpufreq/scaling_max_freq"));
            int hardware = frequency(cpu.resolve("cpufreq/cpuinfo_max_freq"));
            List<LogicalCpuInfo> logical = packages.get(packageId);
            if (logical == null) {
                logical = new ArrayList<>();
                packages.put(packageId, logical);
            }
            // The original four-int DTO omits optional cpuidle telemetry; offline frequency is zero.
            logical.add(new LogicalCpuInfo(current, maximum, hardware, id));
        }
        List<PhysicalCpuInfo> result = new ArrayList<>();
        for (List<LogicalCpuInfo> logical : packages.values()) {
            result.add(new PhysicalCpuInfo(Collections.unmodifiableList(logical)));
        }
        return Collections.unmodifiableList(result);
    }

    static List<PhysicalCpuInfo> physicalCpus() {
        try {
            return topology(CPU);
        } catch (IOException failure) {
            throw unavailable("CPU topology", failure);
        }
    }

    static long[] processStarts(Path proc, int[] pids, LivePid live) throws IOException {
        validatePids(pids);
        long[] starts = new long[pids.length];
        for (int i = 0; i < pids.length; i++) {
            try {
                starts[i] = process(proc, pids[i]).start;
            } catch (NoSuchFileException exited) {
                if (live.exists(pids[i])) {
                    throw new IllegalStateException("Identity stat inaccessible for live PID " + pids[i], exited);
                }
                starts[i] = -1;
            }
        }
        return starts;
    }

    static List<ProcessMemoryUsageInfo> memoryValues(Path proc, int[] pids, long[] values,
            long[] starts, LivePid live) throws IOException {
        validatePids(pids);
        if (values == null || starts == null || values.length != pids.length || starts.length != pids.length) {
            throw new IllegalStateException("PSS result length mismatch");
        }
        long[] after = processStarts(proc, pids, live);
        List<ProcessMemoryUsageInfo> result = new ArrayList<>();
        for (int i = 0; i < pids.length; i++) {
            long value;
            if (after[i] == -1) {
                value = -1;
            } else {
                if (starts[i] < 0 || starts[i] != after[i]) {
                    throw new IllegalStateException("PID reused during PSS request: " + pids[i]);
                }
                if (values[i] <= 0) {
                    throw new IllegalStateException("PSS unavailable or denied for live PID " + pids[i]);
                }
                value = values[i];
            }
            result.add(new ProcessMemoryUsageInfo(pids[i], value));
        }
        return Collections.unmodifiableList(result);
    }

    static List<ProcessMemoryUsageInfo> memory(Context context, int[] pids) {
        try {
            validatePids(pids);
            if (pids.length == 0) return Collections.emptyList();
            ActivityManager manager = activityManager(context);
            LivePid live = livePids(manager);
            long[] starts = processStarts(PROC, pids, live);
            Debug.MemoryInfo[] infos = manager.getProcessMemoryInfo(pids);
            if (infos == null || infos.length != pids.length) {
                throw new IllegalStateException("ActivityManager PSS length mismatch");
            }
            long[] values = new long[pids.length];
            for (int i = 0; i < infos.length; i++) {
                if (infos[i] == null) throw new IllegalStateException("ActivityManager PSS entry missing");
                values[i] = infos[i].getTotalPss();
            }
            return memoryValues(PROC, pids, values, starts, live);
        } catch (IOException failure) {
            throw unavailable("process identity during PSS request", failure);
        }
    }

    private static IllegalStateException unavailable(String metric, IOException cause) {
        return new IllegalStateException("Task Manager metric unavailable: " + metric, cause);
    }
}
