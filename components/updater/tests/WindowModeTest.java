package org.googlebook.pad3.updater;

import java.util.Arrays;

public final class WindowModeTest {
    private static int checks;
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Window mode check " + checks);
        checks++;
    }
    private interface Attempt { void run() throws Exception; }
    private static void rejects(Attempt attempt) throws Exception {
        try { attempt.run(); } catch (Exception expected) { checks++; return; }
        throw new AssertionError("Accepted invalid layout input");
    }
    public static void main(String[] args) throws Exception {
        for (String ending : new String[]{"", "\n", "\r\n"}) {
            check(WindowMode.parse("display windowing mode=fullscreen for displayId=0" + ending) == 1);
            check(WindowMode.parse("display windowing mode=freeform for displayId=0" + ending) == 5);
        }
        for (String invalid : new String[]{"1", "5", "", "display windowing mode=undefined for displayId=0\n",
                "display windowing mode=fullscreen for displayId=1\n", "display windowing mode=freeform for displayId=00\n",
                " display windowing mode=fullscreen for displayId=0\n", "display windowing mode=fullscreen for displayId=0\n5",
                "display windowing mode=fullscreen for displayId=0\n\n", "display windowing mode=fullscreen for displayId=0\r",
                "Error: permission denied\n"})
            rejects(() -> WindowMode.parse(invalid));
        check(Arrays.equals(WindowMode.query(), new String[]{"/system/bin/wm", "get-display-windowing-mode", "-d", "0"}));
        for (int mode : new int[]{1, 5}) {
            check(Arrays.equals(WindowMode.select(mode), new String[]{"/system/bin/wm", "set-display-windowing-mode", "-d", "0", Integer.toString(mode)}));
            check(WindowMode.label(mode).equals(mode == 1 ? "TABLET" : "DESKTOP"));
        }
        for (int invalid : new int[]{-1, 0, 2, 6}) {
            rejects(() -> WindowMode.select(invalid));
            rejects(() -> WindowMode.label(invalid));
        }
        check(WindowMode.requestedUid(new String[]{"status", "1010123"}) == 1010123);
        check(WindowMode.requestedUid(new String[]{"toggle", "1010123"}) == 1010123);
        for (String[] invalid : new String[][]{{}, {"status"}, {"apply", "1010123"}, {"toggle;id", "1010123"},
                {"toggle", "-1"}, {"status", "1010123;id"}, {"toggle", "9999999999"}, {"toggle", "1010123", "5"}})
            rejects(() -> WindowMode.requestedUid(invalid));
        System.out.println("WINDOW_MODE_CHECKS_PASSED=" + checks);
    }
}
