package vendor.google.libraries.desktop.serviceability;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import vendor.google.libraries.desktop.serviceability.ServiceabilityManager.*;

/** Host fixtures exercise real parsing, topology, PID ordering/races and the identity gate. */
public final class MetricsSelfTest {
    private static int checks;
    private interface Action { void run() throws Exception; }

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static void fails(Class<? extends Throwable> type, Action action) throws Exception {
        checks++;
        try { action.run(); }
        catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("Expected " + type + ", got " + failure, failure);
        }
        throw new AssertionError("Expected " + type);
    }

    private static void write(Path path, String value) throws IOException {
        Files.createDirectories(path.getParent());
        Files.write(path, value.getBytes(StandardCharsets.UTF_8));
    }

    private static String stat(int pid, long user, long system, long start) {
        StringBuilder text = new StringBuilder(pid + " (a ) name with ( spaces) S");
        for (int field = 4; field <= 22; field++) {
            text.append(' ').append(field == 14 ? user : field == 15 ? system : field == 22 ? start : 0);
        }
        return text.toString();
    }

    public static void main(String[] args) throws Exception {
        Path root = Paths.get(args[0]);
        Files.createDirectories(root);
        Path battery = root.resolve("battery/charge_full");
        write(battery, "11732000\n");
        check(TaskManagerCompat.capacityMicroAmpHours(battery) == 11732000, "measured full capacity stays in uAh");
        write(battery, "12140000\n");
        check(TaskManagerCompat.capacityMicroAmpHours(battery) == 12140000, "design capacity stays in uAh");
        for (String invalid : new String[]{"", "0", "-1", "1.5", "1 2", "2147483648"}) {
            write(battery, invalid);
            fails(IllegalArgumentException.class, () -> TaskManagerCompat.capacityMicroAmpHours(battery));
        }
        Files.delete(battery);
        fails(IOException.class, () -> TaskManagerCompat.capacityMicroAmpHours(battery));
        String line = "cpu 100 20 30 400 50 6 7 8 999 111\ncpu0 1 2 3";
        CpuUsageInfo cpu = TaskManagerCompat.parseCpu(line, 100);
        check(cpu.userTotalCpuUsage == 120 && cpu.systemTotalCpuUsage == 43 && cpu.totalCpuUsage == 621,
                "CPU sums and guest double-count exclusion");
        check(TaskManagerCompat.ticks(25, 250) == 10, "USER_HZ conversion");
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseCpu("cpu 1 2", 100));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseCpu("cpu0 1 2 3 4 5 6 7 8", 100));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseCpu("cpu -1 2 3 4 5 6 7 8", 100));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.ticks(1, 0));
        fails(ArithmeticException.class, () -> TaskManagerCompat.ticks(Long.MAX_VALUE, 101));

        TaskManagerCompat.ProcStat pid = TaskManagerCompat.parseProcess(321, stat(321, 70, 13, 800));
        check(pid.pid == 321 && pid.user == 70 && pid.system == 13 && pid.start == 800,
                "PID comm parentheses, field offsets and start time");
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseProcess(320, stat(321, 1, 2, 3)));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseProcess(321, "321 (incomplete) S 1"));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.parseProcess(-1, stat(321, 1, 2, 3)));
        check(TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 1000, 1000, () -> true), "system user");
        check(TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 1001000, 1001000, () -> true), "desktop user 10");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 1001000, 1001000, () -> false), "present service");
        check(TaskManagerCompat.selectMode(TaskManagerCompat.DIAGNOSTICS_PACKAGE, 1001000, 1001000, () -> true), "Diagnostics desktop system uid");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.DIAGNOSTICS_PACKAGE, 1001000, 1001000, () -> false), "Diagnostics preserves present vendor service");
        TaskManagerCompat.MissingService forbidden = () -> { throw new AssertionError("lookup must not run"); };
        check(!TaskManagerCompat.selectMode("com.android.settings", 1000, 1000, forbidden), "another system package");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.DIAGNOSTICS_PACKAGE + ".other", 1000, 1000, forbidden), "Diagnostics exact package only");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.DIAGNOSTICS_PACKAGE, 10123, 10123, forbidden), "Diagnostics ordinary uid refused");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.DIAGNOSTICS_PACKAGE, 1001000, 1000, forbidden), "Diagnostics foreign context refused");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 10123, 10123, forbidden), "ordinary uid");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 1001000, 1000, forbidden), "foreign context");
        check(!TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE, 0, 0, forbidden), "root is not Task Manager");
        fails(SecurityException.class, () -> TaskManagerCompat.selectMode(TaskManagerCompat.PACKAGE,
                1001000, 1001000, () -> { throw new SecurityException("denied"); }));

        Path proc = root.resolve("proc");
        write(proc.resolve("stat"), line);
        write(proc.resolve("321/stat"), stat(321, 70, 13, 800));
        write(proc.resolve("42/stat"), stat(42, 25, 5, 900));
        CpuUsageInfoWithProcessUsage processes = TaskManagerCompat.processCpu(proc, new int[]{42, 777, 321}, 100, id -> false);
        check(processes.processCpuUsageInfo.size() == 2, "exited PID has no invented CPU counters");
        check(processes.processCpuUsageInfo.get(0).pid == 42 && processes.processCpuUsageInfo.get(1).pid == 321,
                "CPU request ordering");
        check(processes.processCpuUsageInfo.get(1).userModeTime == 70 && processes.processCpuUsageInfo.get(1).kernelModeTime == 13,
                "process counters are real fixture jiffies");
        check(TaskManagerCompat.processCpu(proc, new int[0], 100, id -> false).processCpuUsageInfo.isEmpty(), "empty CPU PID list");
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.processCpu(proc, new int[]{0}, 100, id -> false));
        fails(IllegalStateException.class, () -> TaskManagerCompat.processCpu(proc,
                new int[]{777}, 100, id -> true));
        fails(SecurityException.class, () -> TaskManagerCompat.processCpu(proc,
                new int[]{777}, 100, id -> { throw new SecurityException("liveness denied"); }));
        fails(IllegalStateException.class, () -> TaskManagerCompat.processStarts(proc,
                new int[]{777}, id -> true));
        Files.createDirectories(proc.resolve("99/stat"));
        fails(IOException.class, () -> TaskManagerCompat.processCpu(proc, new int[]{99}, 100, id -> false));

        int[] order = {42, 321, 777};
        long[] starts = TaskManagerCompat.processStarts(proc, order, id -> false);
        List<ProcessMemoryUsageInfo> memory = TaskManagerCompat.memoryValues(proc, order, new long[]{111, 222, 0}, starts, id -> false);
        check(memory.size() == 3 && memory.get(0).pid == 42 && memory.get(1).pid == 321,
                "PSS input order and PID alignment");
        check(memory.get(0).pssKb == 111 && memory.get(1).pssKb == 222 && memory.get(2).pssKb == -1,
                "real PSS KiB and explicit exited sentinel");
        fails(IllegalStateException.class, () -> TaskManagerCompat.memoryValues(proc, new int[]{42},
                new long[]{0}, new long[]{900}, id -> false));
        fails(IllegalStateException.class, () -> TaskManagerCompat.memoryValues(proc, order, new long[0], starts, id -> false));
        write(proc.resolve("42/stat"), stat(42, 3, 1, 901));
        fails(IllegalStateException.class, () -> TaskManagerCompat.memoryValues(proc, new int[]{42},
                new long[]{111}, new long[]{900}, id -> false));
        Files.delete(proc.resolve("321/stat"));
        check(TaskManagerCompat.memoryValues(proc, new int[]{321}, new long[]{222}, new long[]{800}, id -> false).get(0).pssKb == -1,
                "exit during PSS cannot retain old cached value");

        Path topology = root.resolve("cpu");
        write(topology.resolve("present"), "0-2");
        write(topology.resolve("online"), "0,2");
        for (int id = 0; id < 3; id++) {
            Path node = topology.resolve("cpu" + id);
            write(node.resolve("topology/physical_package_id"), id == 2 ? "1" : "0");
            write(node.resolve("cpufreq/scaling_max_freq"), "2400000");
            write(node.resolve("cpufreq/cpuinfo_max_freq"), "2800000");
            if (id != 1) write(node.resolve("cpufreq/scaling_cur_freq"), "1200000");
        }
        List<PhysicalCpuInfo> physical = TaskManagerCompat.topology(topology);
        check(physical.size() == 2 && physical.get(0).logicalCpus.size() == 2 && physical.get(1).logicalCpus.size() == 1,
                "actual package/logical topology");
        check(physical.get(0).logicalCpus.get(0).currentFrequencyKhz == 1200000, "frequency kHz");
        check(physical.get(0).logicalCpus.get(1).currentFrequencyKhz == 0, "verified offline CPU has zero current frequency");
        check(physical.get(1).logicalCpus.get(0).coreId == 2, "real logical CPU ID");
        check(physical.get(0).logicalCpus.get(0).cStates.isEmpty(), "original DTO permits omitted cpuidle telemetry");
        fails(UnsupportedOperationException.class, () -> physical.clear());
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.cpuIds("0-2,2"));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.cpuIds("3-1"));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.cpuIds("0-4096"));
        fails(IllegalArgumentException.class, () -> TaskManagerCompat.cpuIds(""));
        Files.delete(topology.resolve("cpu2/cpufreq/scaling_cur_freq"));
        fails(IOException.class, () -> TaskManagerCompat.topology(topology));
        write(topology.resolve("cpu2/cpufreq/cpuinfo_cur_freq"), "1300000");
        check(TaskManagerCompat.topology(topology).get(1).logicalCpus.get(0).currentFrequencyKhz == 1300000,
                "real exported alternative frequency");
        write(topology.resolve("cpu2/cpufreq/scaling_max_freq"), "0");
        fails(IllegalStateException.class, () -> TaskManagerCompat.topology(topology));
        System.out.println(checks + " metric/gate fixture checks passed");
    }
}
