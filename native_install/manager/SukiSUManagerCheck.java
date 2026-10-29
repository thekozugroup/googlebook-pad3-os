import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import java.io.File;
import java.security.MessageDigest;

/** Queries only com.sukisu.ultra public package metadata; installs nothing. */
public final class SukiSUManagerCheck {
    private static final String PACKAGE = "com.sukisu.ultra";
    private static final String CERT = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef";
    public static void main(String[] arguments) {
        int result = ManagerDecision.REFUSE;
        try {
            if (arguments.length != 0) throw new IllegalArgumentException("No arguments accepted");
            Object manager = Class.forName("android.app.AppGlobals").getMethod("getPackageManager").invoke(null);
            // GET_SIGNING_CERTIFICATES | MATCH_ANY_USER: include headless/foreground installs.
            PackageInfo info = (PackageInfo) Class.forName("android.content.pm.IPackageManager")
                    .getMethod("getPackageInfo", String.class, long.class, int.class)
                    .invoke(manager, PACKAGE, 0x08000000L | 0x00400000L, 0);
            if (info == null) {
                result = ManagerDecision.INSTALL;
            } else {
                Signature[] signers = info.signingInfo == null ? null : info.signingInfo.getApkContentsSigners();
                StringBuilder digest = new StringBuilder();
                if (signers != null && signers.length == 1) {
                    for (byte value : MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray()))
                        digest.append(String.format("%02x", value & 255));
                }
                String path = info.applicationInfo == null ? "" : info.applicationInfo.sourceDir;
                File source = new File(path);
                boolean canonical = source.isFile() && source.getCanonicalPath().equals(source.getAbsolutePath());
                boolean data = path.startsWith("/data/app/") && path.endsWith("/base.apk");
                boolean system = path.equals("/product/app/SukiSU/SukiSU.apk");
                result = ManagerDecision.decide(true, CERT.equals(digest.toString()), info.getLongVersionCode(), data, system, canonical);
            }
        } catch (Exception error) {
            System.err.println("SukiSU package certificate/path query failed; installation refused");
        }
        System.exit(result);
    }
}
