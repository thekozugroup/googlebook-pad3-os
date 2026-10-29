package vendor.google.libraries.desktop.serviceability;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.Arrays;

/** Host test exercises wire/error semantics; Android transport needs parent runtime verification. */
public final class NativeProcStatsSelfTest {
    private static int checks;
    private interface Action { void run() throws Exception; }
    private static void check(boolean ok) { ++checks; if (!ok) throw new AssertionError(); }
    private static void fails(Class<? extends Throwable> type, Action action) throws Exception {
        ++checks;
        try { action.run(); } catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError(error);
        }
        throw new AssertionError("Expected " + type);
    }
    private static byte[] reply(int status, long user, long system, long start) {
        return ByteBuffer.allocate(40).order(ByteOrder.BIG_ENDIAN).putInt(0x47544d31)
                .putInt(status).putInt(321).putInt(0).putLong(user).putLong(system).putLong(start).array();
    }
    public static void main(String[] args) throws Exception {
        check(Arrays.equals(NativeProcStats.request(321), new byte[]{71,84,77,49,0,0,0,1,0,0,1,65}));
        fails(IllegalArgumentException.class, () -> NativeProcStats.request(0));
        fails(IllegalArgumentException.class, () -> NativeProcStats.request(-1));
        NativeProcStats.requireServerUid(1000);
        fails(IOException.class, () -> NativeProcStats.requireServerUid(0));
        fails(IOException.class, () -> NativeProcStats.requireServerUid(1001000));
        TaskManagerCompat.ProcStat stat = NativeProcStats.decode(321, reply(0, 70, 13, 800));
        check(stat.pid == 321 && stat.user == 70 && stat.system == 13 && stat.start == 800);
        stat = NativeProcStats.decode(321, reply(0, Long.MAX_VALUE, 0, 1));
        check(stat.user == Long.MAX_VALUE && stat.system == 0);
        fails(NoSuchFileException.class, () -> NativeProcStats.decode(321, reply(1, 0, 0, 0)));
        fails(AccessDeniedException.class, () -> NativeProcStats.decode(321, reply(2, 0, 0, 0)));
        for (int code : new int[]{3, 4, 5, -1})
            fails(IOException.class, () -> NativeProcStats.decode(321, reply(code, 0, 0, 0)));
        fails(IOException.class, () -> NativeProcStats.decode(321, reply(1, 1, 0, 0)));
        fails(IOException.class, () -> NativeProcStats.decode(321, reply(0, -1, 0, 0)));
        fails(IOException.class, () -> NativeProcStats.decode(321, reply(0, 0, -1, 0)));
        fails(IOException.class, () -> NativeProcStats.decode(321, reply(0, 0, 0, -1)));
        fails(IOException.class, () -> NativeProcStats.decode(322, reply(0, 1, 2, 3)));
        fails(IOException.class, () -> NativeProcStats.decode(321, new byte[39]));
        fails(IOException.class, () -> NativeProcStats.decode(321, new byte[41]));
        byte[] bad = reply(0, 1, 2, 3); bad[0] = 0;
        fails(IOException.class, () -> NativeProcStats.decode(321, bad));
        byte[] reserved = reply(0, 1, 2, 3); reserved[15] = 1;
        fails(IOException.class, () -> NativeProcStats.decode(321, reserved));
        // Produced by the real C socket handler against a host fixture, not hand-encoded Java.
        byte[] golden = Files.readAllBytes(Paths.get(args[0]));
        stat = NativeProcStats.decode(321, golden);
        check(stat.user == 70 && stat.system == 13 && stat.start == 800);
        System.out.println("NativeProcStats host checks: " + checks);
    }
}
