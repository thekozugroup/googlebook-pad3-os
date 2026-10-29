package vendor.google.libraries.desktop.serviceability;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Compile/test API only. No class from this file may enter the candidate DEX. */
public class ServiceabilityManager {
    public static class CpuUsageInfo {
        public final long userTotalCpuUsage, systemTotalCpuUsage, totalCpuUsage;
        public CpuUsageInfo(long user, long system, long total) {
            userTotalCpuUsage = user; systemTotalCpuUsage = system; totalCpuUsage = total;
        }
    }
    public static class ProcessCpuUsageInfo {
        public final int pid;
        public final long userModeTime, kernelModeTime;
        public ProcessCpuUsageInfo(int pid, long user, long system) {
            this.pid = pid; userModeTime = user; kernelModeTime = system;
        }
    }
    public static class CpuUsageInfoWithProcessUsage {
        public final long userTotalCpuUsage, systemTotalCpuUsage, totalCpuUsage;
        public final List<ProcessCpuUsageInfo> processCpuUsageInfo;
        public CpuUsageInfoWithProcessUsage(long user, long system, long total, List<ProcessCpuUsageInfo> processes) {
            userTotalCpuUsage = user; systemTotalCpuUsage = system; totalCpuUsage = total;
            processCpuUsageInfo = processes;
        }
    }
    public static class ProcessMemoryUsageInfo {
        public final int pid;
        public final long pssKb;
        public ProcessMemoryUsageInfo(int pid, long pss) { this.pid = pid; pssKb = pss; }
    }
    public static class CpuCStateInfo {
        public final String name;
        public final long timeUs;
        public CpuCStateInfo(String name, long time) { this.name = name; timeUs = time; }
    }
    public static class LogicalCpuInfo {
        public final int currentFrequencyKhz, maxFrequencyKhz, maxClockSpeedKhz, coreId;
        public final List<CpuCStateInfo> cStates;
        public LogicalCpuInfo(int current, int maximum, int hardware, int id) {
            this(current, maximum, hardware, id, Collections.emptyList());
        }
        public LogicalCpuInfo(int current, int maximum, int hardware, int id, List<CpuCStateInfo> states) {
            currentFrequencyKhz = current; maxFrequencyKhz = maximum; maxClockSpeedKhz = hardware;
            coreId = id; cStates = Collections.unmodifiableList(new ArrayList<>(states));
        }
    }
    public static class PhysicalCpuInfo {
        public final List<LogicalCpuInfo> logicalCpus;
        public PhysicalCpuInfo(List<LogicalCpuInfo> cpus) { logicalCpus = cpus; }
    }
}
