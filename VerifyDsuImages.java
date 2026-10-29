import java.io.FileInputStream;
import java.security.MessageDigest;

/** Read the same mapped image devices DSU uses; never activate or write images. */
public final class VerifyDsuImages {
    public static void main(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("googlebook-pad3")) {
            throw new IllegalArgumentException("Expected the task-owned slot and three name:size:sha256 entries");
        }
        String[] names = {"system", "system_ext", "product"};
        Class<?> binder = Class.forName("android.os.IBinder");
        Object service = Class.forName("android.os.ServiceManager")
                .getMethod("waitForService", String.class).invoke(null, "gsiservice");
        if (service == null) throw new IllegalStateException("gsiservice unavailable");
        Object gsi = Class.forName("android.gsi.IGsiService$Stub")
                .getMethod("asInterface", binder).invoke(null, service);
        Object images = Class.forName("android.gsi.IGsiService")
                .getMethod("openImageService", String.class).invoke(gsi, "dsu/" + args[0]);
        Class<?> api = Class.forName("android.gsi.IImageService");
        Class<?> mapped = Class.forName("android.gsi.MappedImage");
        for (int i = 0; i < names.length; i++) {
            String[] entry = args[i + 1].split(":");
            if (entry.length != 3 || !entry[0].equals(names[i]) || !entry[2].matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid expected image descriptor");
            }
            long size = Long.parseLong(entry[1]);
            if (size <= 0 || size > 8L * 1024 * 1024 * 1024) throw new IllegalArgumentException("Invalid image size");
            String name = names[i] + "_gsi";
            boolean wasMapped = (Boolean) api.getMethod("isImageMapped", String.class).invoke(images, name);
            try {
                String path;
                if (wasMapped) {
                    path = (String) api.getMethod("getMappedImageDevice", String.class).invoke(images, name);
                } else {
                    Object result = mapped.getDeclaredConstructor().newInstance();
                    api.getMethod("mapImageDevice", String.class, int.class, mapped)
                            .invoke(images, name, 10000, result);
                    path = (String) mapped.getField("path").get(result);
                }
                if (path == null || !path.startsWith("/dev/block/")) throw new IllegalStateException("Invalid mapped device");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long left = size;
                byte[] buffer = new byte[1024 * 1024];
                try (FileInputStream input = new FileInputStream(path)) {
                    while (left > 0) {
                        int count = input.read(buffer, 0, (int) Math.min(left, buffer.length));
                        if (count <= 0) throw new IllegalStateException("Truncated mapped image");
                        digest.update(buffer, 0, count);
                        left -= count;
                    }
                }
                StringBuilder hex = new StringBuilder();
                for (byte value : digest.digest()) {
                    hex.append("0123456789abcdef".charAt((value & 255) >>> 4));
                    hex.append("0123456789abcdef".charAt(value & 15));
                }
                if (!hex.toString().equals(entry[2])) throw new IllegalStateException("Image hash mismatch: " + name);
                System.out.println("MATCH " + name + " " + size + " " + hex);
            } finally {
                if (!wasMapped && (Boolean) api.getMethod("isImageMapped", String.class).invoke(images, name)) {
                    api.getMethod("unmapImageDevice", String.class).invoke(images, name);
                    System.out.println("UNMAPPED " + name);
                }
            }
        }
        System.out.println("ALL_THREE_MAPPED_IMAGES_VERIFIED");
    }
}
