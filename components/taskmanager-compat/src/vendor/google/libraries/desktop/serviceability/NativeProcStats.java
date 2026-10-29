package vendor.google.libraries.desktop.serviceability;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;

/** Only per-PID stat counters. Parent routes real /proc reads here; fixtures stay local. */
final class NativeProcStats {
    private static final String SOCKET = "googlebook_taskmanager_metrics";
    private static final int MAGIC = 0x47544d31;
    private static final int TIMEOUT_MS = 1000;

    private NativeProcStats() {}

    static byte[] request(int pid) {
        if (pid <= 0) throw new IllegalArgumentException("Invalid PID");
        return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
                .putInt(MAGIC).putInt(1).putInt(pid).array();
    }

    static void requireServerUid(int uid) throws IOException {
        if (uid != 1000) throw new IOException("Unexpected TaskManager metrics server UID " + uid);
    }

    static TaskManagerCompat.ProcStat decode(int pid, byte[] response) throws IOException {
        if (pid <= 0 || response.length != 40) throw new IOException("Invalid stat response length or PID");
        ByteBuffer data = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
        int magic = data.getInt(), status = data.getInt(), returnedPid = data.getInt(), reserved = data.getInt();
        long user = data.getLong(), system = data.getLong(), start = data.getLong();
        if (magic != MAGIC || returnedPid != pid || reserved != 0 || user < 0 || system < 0 || start < 0)
            throw new IOException("Invalid stat response fields");
        if (status == 0) return new TaskManagerCompat.ProcStat(pid, user, system, start);
        if (user != 0 || system != 0 || start != 0) throw new IOException("Counters in failed stat response");
        String path = "/proc/" + pid + "/stat";
        if (status == 1) throw new NoSuchFileException(path);
        if (status == 2) throw new AccessDeniedException(path);
        if (status == 3) throw new IOException("Stat request rejected for PID " + pid);
        if (status == 4) throw new IOException("Stat unavailable for PID " + pid);
        throw new IOException("Unknown stat response status " + status);
    }

    private static void waitFor(FileDescriptor fd, short events, long deadline) throws IOException, ErrnoException {
        for (;;) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) throw new SocketTimeoutException("TaskManager metrics deadline");
            StructPollfd poll = new StructPollfd();
            poll.fd = fd;
            poll.events = events;
            try {
                int result = Os.poll(new StructPollfd[]{poll}, (int)((remaining + 999999) / 1000000));
                if (result == 0) throw new SocketTimeoutException("TaskManager metrics deadline");
                if ((poll.revents & OsConstants.POLLNVAL) != 0) throw new IOException("Invalid metrics socket");
                return;
            } catch (ErrnoException error) {
                if (error.errno != OsConstants.EINTR) throw error;
            }
        }
    }

    private static int io(FileDescriptor fd, byte[] bytes, int offset, int count,
            boolean writing, long deadline) throws IOException, ErrnoException {
        for (;;) {
            waitFor(fd, (short)(writing ? OsConstants.POLLOUT : OsConstants.POLLIN), deadline);
            try {
                return writing ? Os.write(fd, bytes, offset, count) : Os.read(fd, bytes, offset, count);
            } catch (ErrnoException error) {
                if (error.errno != OsConstants.EINTR && error.errno != OsConstants.EAGAIN) throw error;
            }
        }
    }

    static TaskManagerCompat.ProcStat read(int pid) throws IOException {
        byte[] request = request(pid);
        long deadline = System.nanoTime() + TIMEOUT_MS * 1000000L;
        try (LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_STREAM)) {
            socket.getInputStream(); // LocalSocket creates its FD lazily; option setters do not.
            socket.setSoTimeout(TIMEOUT_MS);
            FileDescriptor fd = socket.getFileDescriptor();
            Os.fcntlInt(fd, OsConstants.F_SETFL, Os.fcntlInt(fd, OsConstants.F_GETFL, 0) | OsConstants.O_NONBLOCK);
            // LocalSocket.connect(address, timeout) is unimplemented. AF_UNIX nonblocking connect
            // instead fails immediately if the listener/backlog is unavailable; no unbounded retry.
            socket.connect(new LocalSocketAddress(SOCKET, LocalSocketAddress.Namespace.RESERVED));
            requireServerUid(socket.getPeerCredentials().getUid());
            for (int offset = 0; offset < request.length;) {
                int n = io(fd, request, offset, request.length - offset, true, deadline);
                if (n <= 0) throw new IOException("Metrics request truncated");
                offset += n;
            }
            socket.shutdownOutput();
            byte[] response = new byte[40];
            for (int offset = 0; offset < response.length;) {
                int n = io(fd, response, offset, response.length - offset, false, deadline);
                if (n <= 0) throw new IOException("Metrics response truncated");
                offset += n;
            }
            if (io(fd, new byte[1], 0, 1, false, deadline) != 0)
                throw new IOException("Metrics response has trailing data");
            return decode(pid, response);
        } catch (ErrnoException error) {
            throw new IOException("TaskManager metrics socket failed", error);
        }
    }
}
