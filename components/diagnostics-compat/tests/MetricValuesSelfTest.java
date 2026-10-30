package org.googlebook.pad3.diagnostics;

import java.util.Arrays;
import java.util.Locale;

public final class MetricValuesSelfTest {
    private static int checks;
    private static void check(boolean value) { checks++; if (!value) throw new AssertionError(checks); }
    public static void main(String[] args) {
        check(MetricValues.allowed(MetricValues.TARGET, 1001000, MetricValues.APK_SHA));
        check(!MetricValues.allowed(MetricValues.TARGET + ".other", 1001000, MetricValues.APK_SHA));
        check(!MetricValues.allowed(MetricValues.TARGET, 1010200, MetricValues.APK_SHA));
        check(!MetricValues.allowed(MetricValues.TARGET, 1001000, "different"));
        check(Arrays.equals(MetricValues.memory(12000, 7000), new long[]{5000, 12000}));
        check(MetricValues.memory(0, 0)[0] == Long.MIN_VALUE);
        check(MetricValues.memory(10, 11)[0] == Long.MIN_VALUE);
        check(MetricValues.memory(10, -1)[0] == Long.MIN_VALUE);
        check(MetricValues.bytes(1073741824L, 0, 2, 2, Locale.US).equals("1.00 GiB"));
        check(MetricValues.bytes(1536, 0, 0, 2, Locale.US).equals("1.5 KiB"));
        check(MetricValues.bytes(0, 0, 0, 2, Locale.US).equals("0 B"));
        check(MetricValues.bytes(-1, 0, 2, 2, Locale.US).equals("Unavailable"));
        check(MetricValues.bytes(Double.NaN, 0, 2, 2, Locale.US).equals("Unavailable"));
        check(MetricValues.health("100\n") == 100);
        for (String value : new String[]{"0", "-1", "101", "", "1.5", "100 extra"}) {
            boolean rejected = false;
            try { MetricValues.health(value); } catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected);
        }
        MetricValues.CpuHistory cpu = new MetricValues.CpuHistory();
        check(cpu.sample(10, 20, 100) == null && cpu.series().isEmpty());
        check(Arrays.equals(cpu.sample(30, 30, 200), new int[]{20, 10, 30}));
        check(cpu.series().get(0).equals(Arrays.asList(30)));
        check(cpu.series().stream().allMatch(series -> series.get(0) >= 0));
        for (int i = 1; i <= 100; i++) cpu.sample(30 + i, 30 + i, 200 + 100 * i);
        check(cpu.series().get(0).size() == 61 && cpu.series().get(1).size() == 61);
        check(cpu.sample(1, 1, 10) == null && cpu.series().isEmpty());
        System.out.println(checks + " Diagnostics metric and scope checks passed");
    }
}
