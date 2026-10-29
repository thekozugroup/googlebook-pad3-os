package org.googlebook.pad3.updater;

/** Exact internal-display protocol; no caller-supplied shell commands or display IDs. */
final class WindowMode {
    static int requestedUid(String[] args) throws Exception {
        UpdateCore.require(args.length == 2 && (args[0].equals("status") || args[0].equals("toggle"))
                && args[1].matches("[0-9]{1,10}"), "Unknown layout operation/UID");
        return Integer.parseInt(args[1]);
    }
    static int parse(String output) throws Exception {
        UpdateCore.require(output.matches("display windowing mode=(fullscreen|freeform) for displayId=0(?:\r?\n)?"),
                "Unsupported internal display mode");
        return output.startsWith("display windowing mode=fullscreen ") ? 1 : 5;
    }
    static String[] query() {
        return new String[]{"/system/bin/wm", "get-display-windowing-mode", "-d", "0"};
    }
    static String[] select(int mode) throws Exception {
        UpdateCore.require(mode == 1 || mode == 5, "Unsupported layout mode");
        return new String[]{"/system/bin/wm", "set-display-windowing-mode", "-d", "0", mode == 1 ? "1" : "5"};
    }
    static String label(int mode) throws Exception {
        UpdateCore.require(mode == 1 || mode == 5, "Unsupported layout mode");
        return mode == 1 ? "TABLET" : "DESKTOP";
    }
}
