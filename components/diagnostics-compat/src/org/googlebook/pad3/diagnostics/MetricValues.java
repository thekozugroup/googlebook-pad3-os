package org.googlebook.pad3.diagnostics;

import java.text.NumberFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Unit conversions and collected samples; no Android or privileged operations. */
public final class MetricValues {
    public static final String TARGET = "com.google.android.factory.diagnostics";
    public static final String APK_SHA = "efc1408bbbceb9d3b7b3f70a307d42ff8194e481ecec5a40d1b9d17d39ffcb83";
    public static final String UNAVAILABLE = "Unavailable";

    public static boolean allowed(String name, int uid, String digest) {
        return TARGET.equals(name) && uid >= 0 && uid % 100000 == 1000 && APK_SHA.equals(digest);
    }

    public static long[] memory(long total, long available) {
        return total > 0 && available >= 0 && available <= total
                ? new long[]{total - available, total} : new long[]{Long.MIN_VALUE, Long.MIN_VALUE};
    }

    public static int health(String text) {
        if (!text.trim().matches("[0-9]{1,3}")) throw new IllegalArgumentException("Invalid battery health");
        int value = Integer.parseInt(text.trim());
        if (value < 1 || value > 100) throw new IllegalArgumentException("Battery health unavailable");
        return value;
    }

    public static String bytes(Number number, int unit, int minimum, int maximum, Locale locale) {
        double value = number.doubleValue();
        if (value < 0 || !Double.isFinite(value)) return UNAVAILABLE;
        String[] units = {"B", "KiB", "MiB", "GiB", "TiB"};
        if (unit < 0 || unit >= units.length) throw new IllegalArgumentException("Unknown size unit");
        while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
        NumberFormat format = NumberFormat.getNumberInstance(locale);
        format.setMaximumFractionDigits(maximum);
        format.setMinimumFractionDigits(minimum);
        return format.format(value) + " " + units[unit];
    }

    public static final class CpuHistory {
        private long user, system, total;
        private boolean seeded;
        private final ArrayDeque<Integer> totals = new ArrayDeque<>(), systems = new ArrayDeque<>();

        public int[] sample(long nextUser, long nextSystem, long nextTotal) {
            boolean valid = seeded && nextTotal > total && nextUser >= user && nextSystem >= system;
            long delta = nextTotal - total, du = nextUser - user, ds = nextSystem - system;
            valid &= delta > 0 && du >= 0 && ds >= 0 && du <= delta && ds <= delta - du;
            if (!seeded || nextTotal < total || nextUser < user || nextSystem < system) {
                totals.clear(); systems.clear();
            }
            user = nextUser; system = nextSystem; total = nextTotal; seeded = true;
            if (!valid) return null;
            int users = (int) (100.0 * du / delta), sys = (int) (100.0 * ds / delta);
            totals.addFirst(users + sys); systems.addFirst(sys);
            if (totals.size() > 61) { totals.removeLast(); systems.removeLast(); }
            return new int[]{users, sys, users + sys};
        }

        public List<List<Integer>> series() {
            // The donor renderer calls first() on each series before drawing its marker.
            if (totals.isEmpty()) return Collections.emptyList();
            return Arrays.asList(new ArrayList<>(totals), new ArrayList<>(systems));
        }
    }
}
