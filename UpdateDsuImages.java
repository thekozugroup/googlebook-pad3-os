import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;

/** Update only the three read-only partitions of the existing task-owned DSU. */
public final class UpdateDsuImages {
    private static final String SLOT = "googlebook-pad3";
    private static final String[] NAMES = {"system", "system_ext", "product"};

    private static String hash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (FileInputStream stream = new FileInputStream(file)) {
            int size;
            while ((size = stream.read(buffer)) != -1) digest.update(buffer, 0, size);
        }
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) hex.append(String.format("%02x", value & 255));
        return hex.toString();
    }

    public static void main(String[] args) {
        try {
            update(args);
        } catch (Throwable error) {
            error.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void update(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Expected three name:size:sha256:path descriptors");
        File[] files = new File[3];
        long[] sizes = new long[3];
        for (int i = 0; i < 3; i++) {
            String[] descriptor = args[i].split(":", 4);
            if (descriptor.length != 4 || !descriptor[0].equals(NAMES[i])
                    || !descriptor[2].matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Only system, system_ext, product are permitted, in that order");
            }
            sizes[i] = Long.parseLong(descriptor[1]);
            files[i] = new File(descriptor[3]);
            if (sizes[i] <= 0 || sizes[i] > 4L * 1024 * 1024 * 1024 || sizes[i] % 512 != 0
                    || !files[i].getCanonicalPath().startsWith("/data/local/tmp/googlebook-dsu-stage/")
                    || Files.isSymbolicLink(files[i].toPath()) || !files[i].isFile()
                    || files[i].length() != sizes[i] || !hash(files[i]).equals(descriptor[2])) {
                throw new IllegalArgumentException("Invalid or changed input image: " + NAMES[i]);
            }
            System.out.println("INPUT_VERIFIED " + NAMES[i] + " " + descriptor[2]);
        }
        int uid = (Integer) Class.forName("android.os.Process").getMethod("myUid").invoke(null);
        if (uid != 0) throw new IllegalStateException("Root is required");
        File metadata = new File("/metadata/gsi/dsu/" + SLOT);
        File pointer = new File(metadata, "metadata_encryption_dir");
        byte[] previousPointer = Files.readAllBytes(pointer.toPath());
        String install = new String(Files.readAllBytes(new File(metadata, "install_dir").toPath()), "UTF-8").trim();
        if (!install.matches("/data/gsi/dsu/" + SLOT + "/?")) throw new IllegalStateException("Unexpected install directory");
        File userdata = new File(install, "userdata_gsi.img.0000");
        long userdataSize = userdata.length(), userdataTime = userdata.lastModified();
        if (!userdata.isFile() || userdataSize != 8L * 1024 * 1024 * 1024) {
            throw new IllegalStateException("Expected the existing 8 GiB test userdata");
        }
        Object service = Class.forName("android.os.ServiceManager").getMethod("waitForService", String.class)
                .invoke(null, "gsiservice");
        Class<?> binder = Class.forName("android.os.IBinder");
        Object gsi = Class.forName("android.gsi.IGsiService$Stub").getMethod("asInterface", binder).invoke(null, service);
        Class<?> api = Class.forName("android.gsi.IGsiService");
        if ((Boolean) api.getMethod("isGsiRunning").invoke(gsi)
                || (Boolean) api.getMethod("isGsiEnabled").invoke(gsi)) {
            throw new IllegalStateException("DSU must be disabled and not running");
        }
        Class<?> descriptorClass = Class.forName("android.os.ParcelFileDescriptor");
        boolean opened = false, partition = false;
        try {
            int result = (Integer) api.getMethod("openInstall", String.class).invoke(gsi, install);
            if (result != 0) throw new IllegalStateException("openInstall failed: " + result);
            opened = true;
            for (int i = 0; i < 3; i++) {
                result = (Integer) api.getMethod("createPartition", String.class, long.class, boolean.class)
                        .invoke(gsi, NAMES[i], sizes[i], true);
                if (result != 0) throw new IllegalStateException("createPartition failed: " + NAMES[i] + " " + result);
                partition = true;
                Object descriptor = descriptorClass.getMethod("open", File.class, int.class)
                        .invoke(null, files[i], 0x10000000);
                try {
                    if (!(Boolean) api.getMethod("commitGsiChunkFromStream", descriptorClass, long.class)
                            .invoke(gsi, descriptor, sizes[i])) {
                        throw new IllegalStateException("Image stream failed: " + NAMES[i]);
                    }
                } finally {
                    ((Closeable) descriptor).close();
                }
                result = (Integer) api.getMethod("closePartition").invoke(gsi);
                partition = false;
                if (result != 0) throw new IllegalStateException("closePartition failed: " + NAMES[i] + " " + result);
                System.out.println("PARTITION_COMMITTED " + NAMES[i]);
            }
        } finally {
            try {
                if (partition) {
                    int result = (Integer) api.getMethod("closePartition").invoke(gsi);
                    System.err.println("FAILURE_CLOSE_PARTITION " + result);
                }
            } finally {
                if (opened) {
                    int result = (Integer) api.getMethod("closeInstall").invoke(gsi);
                    if (result != 0) throw new IllegalStateException("Finalization failed; do not reboot: " + result);
                    System.out.println("INSTALL_FINALIZED_DISABLED");
                }
            }
        }
        if ((Boolean) api.getMethod("isGsiEnabled").invoke(gsi)
                || !new File(metadata, "complete").isFile()
                || !Arrays.equals(previousPointer, Files.readAllBytes(pointer.toPath()))
                || userdata.length() != userdataSize || userdata.lastModified() != userdataTime) {
            throw new IllegalStateException("DSU disabled/completion/userdata preservation check failed");
        }
        System.out.println("THREE_IMAGES_UPDATED_USERDATA_RETAINED");
    }
}
