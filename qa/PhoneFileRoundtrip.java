import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

/** Opt-in, privileged paired-phone probe. See PHONE_INTEGRATION.md before running. */
public final class PhoneFileRoundtrip {
    static final int READ_LIMIT = 4096;
    static final String PROVIDER = "com.google.ambient.streaming.multidevicesync.quickaccess";
    static final String DIRECTORY = "vnd.android.document/directory";
    static final String PNG = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKUlEQVR4nGNg6LlDWzRqwagFoxaMWjBqwagFoxaMWjBqwagFoxYMFQsAm4igTGbY2bMAAAAASUVORK5CYII=";
    static final String[] PROJECTION = {"document_id", "_display_name", "mime_type", "flags"};

    static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("probe validation failed");
    }

    static void opaque(String value) {
        require(value != null && !value.isEmpty() && value.length() <= 2048);
        require(value.equals(value.trim()));
        for (int i = 0; i < value.length(); i++) require(!Character.isISOControl(value.charAt(i)));
    }

    static final class Options {
        final int user;
        final String root, directory, mode, authority, mime;
        Options(String[] args) {
            require(args.length == 4 && args[0].matches("[1-9][0-9]{0,4}"));
            user = Integer.parseInt(args[0]);
            require(user <= Integer.MAX_VALUE / 100000);
            opaque(args[1]);
            require(args[2].matches("/data/local/tmp/googlebook-phone-probe-[A-Za-z0-9][A-Za-z0-9_-]{0,63}"));
            require("text".equals(args[3]) || "image".equals(args[3]));
            root = args[1]; directory = args[2]; mode = args[3];
            authority = user + "@" + PROVIDER;
            mime = "image".equals(mode) ? "image/png" : "text/plain";
        }
    }

    static byte[] payload(String mode, String nonce) {
        require(nonce != null && nonce.matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"));
        require("text".equals(mode) || "image".equals(mode));
        byte[] bytes = "image".equals(mode) ? Base64.getDecoder().decode(PNG)
                : ("Googlebook paired-phone file roundtrip probe.\nnonce=" + nonce + "\n").getBytes(StandardCharsets.UTF_8);
        require(bytes.length > 0 && bytes.length <= READ_LIMIT);
        return bytes;
    }

    static byte[] readBounded(InputStream input) throws Exception {
        require(input != null);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[256];
        int count;
        while ((count = input.read(buffer, 0, Math.min(buffer.length, READ_LIMIT + 1 - output.size()))) != -1) {
            require(count > 0 && output.size() + count <= READ_LIMIT);
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    static void thumbnailPixel(int pixel) {
        require(((pixel >>> 16) & 255) <= 4);
        require(Math.abs(((pixel >>> 8) & 255) - 140) <= 4);
        require(Math.abs((pixel & 255) - 220) <= 4);
    }

    static final class Row {
        final String id, name, mime;
        final int flags;
        Row(String id, String name, String mime, int flags) {
            opaque(id); this.id = id; this.name = name; this.mime = mime; this.flags = flags;
        }
    }

    static Row ownedRow(List<Row> rows, Set<String> baseline, String name, String mime, String expectedId) {
        Row match = null;
        for (Row row : rows) if (name.equals(row.name)) {
            require(match == null && mime.equals(row.mime) && !baseline.contains(row.id));
            require(expectedId == null || expectedId.equals(row.id));
            match = row;
        }
        return match;
    }

    // Android-dependent work stays out of the JDK-only self-test path.
    static final class Live {
        final Options options;
        final Properties receipt = new Properties();
        final File directory, receiptFile, nextFile;
        long device, inode;

        Live(Options options) throws Exception {
            this.options = options;
            directory = new File(options.directory);
            receiptFile = new File(directory, "receipt.properties");
            nextFile = new File(directory, "receipt.properties.next");
            verifyDirectory();
            require(!receiptFile.exists() && !nextFile.exists());
            // O_EXCL also rejects dangling symlinks and concurrent runs sharing this directory.
            try (FileOutputStream out = new FileOutputStream(Os.open(receiptFile.getPath(),
                    OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL | OsConstants.O_NOFOLLOW, 0600))) {
                out.getFD().sync();
            }
            receipt.setProperty("android_user", Integer.toString(options.user));
            receipt.setProperty("selected_root_id", options.root);
            receipt.setProperty("authority", options.authority);
            receipt.setProperty("mode", options.mode);
            receipt.setProperty("status", "started");
            save();
        }

        void verifyDirectory() throws Exception {
            require(directory.getCanonicalPath().equals(options.directory));
            StructStat stat = Os.lstat(options.directory);
            require(OsConstants.S_ISDIR(stat.st_mode) && (stat.st_mode & 07777) == 0700);
            require(stat.st_uid == 1000 && stat.st_gid == 1000);
            if (inode != 0) require(device == stat.st_dev && inode == stat.st_ino);
            device = stat.st_dev; inode = stat.st_ino;
        }

        void save() throws Exception {
            verifyDirectory();
            try (FileOutputStream out = new FileOutputStream(Os.open(nextFile.getPath(),
                    OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL | OsConstants.O_NOFOLLOW, 0600))) {
                receipt.store(out, "PRIVATE: paired-phone probe recovery resources");
                out.getFD().sync();
            }
            Os.rename(nextFile.getPath(), receiptFile.getPath());
            FileDescriptor fd = Os.open(options.directory, OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
            try { Os.fsync(fd); } finally { Os.close(fd); }
        }

        void state(String state) throws Exception { receipt.setProperty("status", state); save(); }

        final class External implements AutoCloseable {
            Object manager;
            IBinder token;
            ContentProviderClient client;
            boolean acquired;
            ContentResolver open(Context context) throws Exception {
                manager = Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
                token = new Binder();
                Object holder = Class.forName("android.app.IActivityManager").getMethod("getContentProviderExternal",
                        String.class, int.class, IBinder.class, String.class)
                        .invoke(manager, PROVIDER, options.user, token, "googlebook-phone-probe");
                acquired = holder != null;
                require(acquired);
                Object provider = holder.getClass().getField("provider").get(holder);
                require(provider != null);
                // A normal system-context resolver uses an unregistered app thread in app_process.
                client = (ContentProviderClient) ContentProviderClient.class.getConstructor(ContentResolver.class,
                        Class.forName("android.content.IContentProvider"), boolean.class)
                        .newInstance(context.getContentResolver(), provider, false);
                return ContentResolver.wrap(client);
            }
            @Override public void close() throws Exception {
                try { if (client != null) client.close(); }
                finally {
                    if (acquired) Class.forName("android.app.IActivityManager")
                            .getMethod("removeContentProviderExternalAsUser", String.class, IBinder.class, int.class)
                            .invoke(manager, PROVIDER, token, options.user);
                }
            }
        }

        List<Row> children(ContentResolver resolver, String parent) throws Exception {
            resolver.refresh(DocumentsContract.buildDocumentUri(options.authority, parent), null, null);
            for (int attempt = 0; attempt < 24; attempt++) {
                List<Row> rows = new ArrayList<>();
                Set<String> ids = new HashSet<>();
                boolean loading;
                try (Cursor cursor = resolver.query(DocumentsContract.buildChildDocumentsUri(options.authority, parent),
                        PROJECTION, null, null, null)) {
                    require(cursor != null);
                    loading = cursor.getExtras().getBoolean(DocumentsContract.EXTRA_LOADING, false);
                    while (cursor.moveToNext()) {
                        require(rows.size() < 10000 && ids.add(cursor.getString(0)));
                        rows.add(new Row(cursor.getString(0), cursor.getString(1), cursor.getString(2), cursor.getInt(3)));
                    }
                }
                if (!loading) return rows;
                SystemClock.sleep(250);
            }
            throw new IllegalStateException("listing incomplete");
        }

        String selectedRoot(ContentResolver resolver) throws Exception {
            String root = null;
            int count = 0;
            try (Cursor cursor = resolver.query(DocumentsContract.buildRootsUri(options.authority),
                    new String[]{"root_id", "document_id"}, null, null, null)) {
                require(cursor != null && !cursor.getExtras().getBoolean(DocumentsContract.EXTRA_LOADING, false));
                while (cursor.moveToNext()) {
                    require(++count <= 10000);
                    if (options.root.equals(cursor.getString(0))) {
                        require(root == null); root = cursor.getString(1); opaque(root);
                    }
                }
            }
            require(root != null);
            receipt.setProperty("root_document_id", root);
            return root;
        }

        void roundtrip(ContentResolver resolver) throws Exception {
            String parent = null;
            for (Row row : children(resolver, selectedRoot(resolver)))
                if ("Download".equals(row.name) && DIRECTORY.equals(row.mime)) {
                    require(parent == null && (row.flags & DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE) != 0);
                    parent = row.id;
                }
            require(parent != null);
            String nonce = UUID.randomUUID().toString();
            String name = "googlebook-probe-" + nonce + ("image".equals(options.mode) ? ".png" : ".txt");
            byte[] bytes = payload(options.mode, nonce);
            Set<String> baseline = new HashSet<>();
            for (Row row : children(resolver, parent)) {
                require(!name.equals(row.name)); baseline.add(row.id);
            }
            receipt.setProperty("parent_document_id", parent);
            receipt.setProperty("name", name);
            receipt.setProperty("mime", options.mime);
            receipt.setProperty("baseline_count", Integer.toString(baseline.size()));
            int index = 0;
            for (String id : baseline) receipt.setProperty("baseline." + index++, id);
            state("planned");
            String createdId = null;
            boolean verified = false;
            try {
                Uri created = DocumentsContract.createDocument(resolver,
                        DocumentsContract.buildDocumentUri(options.authority, parent), options.mime, name);
                require(created != null);
                receipt.setProperty("created_uri", created.toString());
                state("uri_recorded"); // Persist the returned URI before opening any write stream.
                require("content".equals(created.getScheme()) && options.authority.equals(created.getAuthority()));
                require(created.getQuery() == null && created.getFragment() == null);
                createdId = DocumentsContract.getDocumentId(created); opaque(createdId);
                require(!baseline.contains(createdId));
                require(ownedRow(children(resolver, parent), baseline, name, options.mime, createdId) != null);
                verifyDocument(resolver, created, createdId, name);
                receipt.setProperty("owned", "true"); state("owned");
                try (OutputStream output = resolver.openOutputStream(created, "w")) {
                    require(output != null); output.write(bytes);
                }
                try (InputStream input = resolver.openInputStream(created)) {
                    require(Arrays.equals(bytes, readBounded(input)));
                }
                receipt.setProperty("verified_bytes", Integer.toString(bytes.length)); state("content_verified");
                if ("image".equals(options.mode)) {
                    children(resolver, parent);
                    android.graphics.Bitmap thumbnail = resolver.loadThumbnail(created, new android.util.Size(32, 32), null);
                    require(thumbnail != null);
                    try {
                        require(thumbnail.getWidth() == 32 && thumbnail.getHeight() == 32);
                        int pixel = thumbnail.getPixel(16, 16);
                        thumbnailPixel(pixel);
                        receipt.setProperty("thumbnail_center_argb", Integer.toHexString(pixel));
                    }
                    finally { thumbnail.recycle(); }
                    receipt.setProperty("thumbnail", "32x32"); state("thumbnail_verified");
                }
                verified = true;
            } finally {
                // A lost create response is recoverable only through this random name and the saved baseline.
                Row owned = ownedRow(children(resolver, parent), baseline, name, options.mime, createdId);
                if (owned != null) {
                    Uri uri = DocumentsContract.buildDocumentUri(options.authority, owned.id);
                    verifyDocument(resolver, uri, owned.id, name);
                    receipt.setProperty("cleanup_uri", uri.toString());
                    // Receipt failure must not prevent an otherwise proven owned-file cleanup.
                    try { state("deleting"); } catch (Exception ignored) { }
                    require(DocumentsContract.deleteDocument(resolver, uri));
                    for (Row row : children(resolver, parent)) require(!owned.id.equals(row.id) && !name.equals(row.name));
                    receipt.setProperty("deletion_verified", "true"); state("deleted");
                } else {
                    receipt.setProperty("owned_file_absent", "true"); state("absent");
                }
            }
            require(verified && "true".equals(receipt.getProperty("deletion_verified")));
        }

        void verifyDocument(ContentResolver resolver, Uri uri, String id, String name) throws Exception {
            try (Cursor cursor = resolver.query(uri, PROJECTION, null, null, null)) {
                require(cursor != null && cursor.moveToFirst());
                require(id.equals(cursor.getString(0)) && name.equals(cursor.getString(1)) && options.mime.equals(cursor.getString(2)));
                require(!cursor.moveToNext());
            }
        }

        void run() throws Exception {
            try {
                Looper.prepareMainLooper();
                Object thread = Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
                Context context = (Context) thread.getClass().getMethod("getSystemContext").invoke(thread);
                try (External external = new External()) { roundtrip(external.open(context)); }
                state("complete");
            } catch (Exception failure) {
                receipt.setProperty("failure_class", failure.getClass().getName());
                try { state("failed_review_receipt"); } catch (Exception ignored) { }
                throw failure;
            }
        }
    }

    interface Check { void run() throws Exception; }
    static void rejects(Check check) throws Exception {
        try { check.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid input accepted");
    }

    static void selfTest() throws Exception {
        String[] good = {"1", "selected-root", "/data/local/tmp/googlebook-phone-probe-self_test-1", "text"};
        Options options = new Options(good);
        require(options.user == 1 && options.authority.equals("1@" + PROVIDER) && options.mime.equals("text/plain"));
        rejects(() -> new Options(new String[0]));
        rejects(() -> new Options(new String[]{good[0], good[1], good[2], good[3], "extra"}));
        String[] maximum = {"21474", new String(new char[2048]).replace('\0', 'r'),
                "/data/local/tmp/googlebook-phone-probe-" + new String(new char[64]).replace('\0', 's'), "image"};
        require(new Options(maximum).mime.equals("image/png"));
        for (String user : new String[]{"0", "-1", "+1", "01", "1 ", "21475", "99999999999"}) {
            String[] bad = good.clone(); bad[0] = user; rejects(() -> new Options(bad));
        }
        for (String root : new String[]{"", " ", "root\nother", new String(new char[2049]).replace('\0', 'x')}) {
            String[] bad = good.clone(); bad[1] = root; rejects(() -> new Options(bad));
        }
        for (String path : new String[]{"/data/user/1/app", "/data/local/tmp", good[2] + "/", good[2] + "/../other",
                "/data/local/tmp/googlebook-phone-probe-", "/data/local/tmp/googlebook-phone-probe-a.b", good[2] + "\n",
                maximum[2] + "s"}) {
            String[] bad = good.clone(); bad[2] = path; rejects(() -> new Options(bad));
        }
        for (String mode : new String[]{"", "TEXT", "video", "image "}) {
            String[] bad = good.clone(); bad[3] = mode; rejects(() -> new Options(bad));
        }
        String nonce = "00000000-0000-0000-0000-000000000000";
        byte[] text = payload("text", nonce), image = payload("image", nonce);
        require(new String(text, StandardCharsets.UTF_8).contains(nonce) && text.length == 89);
        require(image.length == 98 && image[0] == (byte) 137 && image[1] == 'P' && image[2] == 'N' && image[3] == 'G');
        require(image[19] == 32 && image[23] == 32);
        thumbnailPixel(0xff008cdc);
        thumbnailPixel(0xff0488d8); thumbnailPixel(0xff0490e0);
        rejects(() -> thumbnailPixel(0xff058cdc));
        rejects(() -> thumbnailPixel(0xff0087dc)); rejects(() -> thumbnailPixel(0xff0091dc));
        rejects(() -> thumbnailPixel(0xff008cd7)); rejects(() -> thumbnailPixel(0xff008ce1));
        rejects(() -> thumbnailPixel(0xffffffff)); rejects(() -> thumbnailPixel(0xff000000));
        rejects(() -> payload("video", nonce)); rejects(() -> payload("text", "../unsafe"));
        require(Arrays.equals(text, readBounded(new ByteArrayInputStream(text))));
        require(Arrays.equals(image, readBounded(new ByteArrayInputStream(image))));
        require(readBounded(new ByteArrayInputStream(new byte[READ_LIMIT])).length == READ_LIMIT);
        rejects(() -> readBounded(new ByteArrayInputStream(new byte[READ_LIMIT + 1])));
        rejects(() -> readBounded(null));
        Set<String> baseline = new HashSet<>(Arrays.asList("old"));
        Row row = new Row("new", "random.txt", "text/plain", 0);
        List<Row> rows = Arrays.asList(row);
        require(ownedRow(rows, baseline, row.name, row.mime, "new") == row);
        require(ownedRow(rows, baseline, row.name, row.mime, null) == row);
        require(ownedRow(rows, baseline, "absent", row.mime, null) == null);
        rejects(() -> ownedRow(rows, baseline, row.name, row.mime, "wrong"));
        rejects(() -> ownedRow(rows, baseline, row.name, "image/png", null));
        rejects(() -> ownedRow(Arrays.asList(row, row), baseline, row.name, row.mime, null));
        rejects(() -> ownedRow(Arrays.asList(new Row("old", row.name, row.mime, 0)), baseline, row.name, row.mime, null));
        System.out.println("PHONE_FILE_SELF_TEST_PASS");
    }

    public static void main(String[] args) {
        int status = 0;
        try {
            if (args.length == 1 && "--self-test".equals(args[0])) selfTest();
            else {
                Options options = new Options(args);
                Os.setgid(1000); Os.setuid(1000);
                require(Os.getuid() == 1000 && Os.getgid() == 1000);
                Os.umask(0077);
                new Live(options).run();
                System.out.println("PHONE_FILE_ROUNDTRIP_PASS mode=" + options.mode + " deletion_verified=true");
            }
        } catch (Throwable failure) {
            // Provider exceptions can contain account IDs, peer IDs, document IDs or private paths.
            System.err.println("PHONE_FILE_ROUNDTRIP_FAIL: review the private receipt; do not retry blindly");
            status = 1;
        }
        System.exit(status);
    }
}
