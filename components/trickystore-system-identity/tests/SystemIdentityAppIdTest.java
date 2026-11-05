import java.util.Arrays;
import org.googlebook.pad3.compat.SystemIdentityAppId;

public final class SystemIdentityAppIdTest {
    public static void main(String[] args) {
        byte[] expected = java.util.HexFormat.of().parseHex(
                "301831143012040d416e64726f696453797374656d0201013100");
        for (int uid : new int[]{0,1000}) {
            byte[] first = SystemIdentityAppId.forUid(uid);
            if (!Arrays.equals(expected, first)) throw new AssertionError("system DER");
            first[0] = 0;
            if (!Arrays.equals(expected, SystemIdentityAppId.forUid(uid)))
                throw new AssertionError("shared mutable array");
        }
        for (int uid : new int[]{-1,1,999,1001,10000,1010151,1001000,Integer.MAX_VALUE})
            if (SystemIdentityAppId.forUid(uid) != null)
                throw new AssertionError("ordinary UID changed: " + uid);
        System.out.println("PASS: exact AOSP root/system identity; other UIDs unchanged; fresh arrays");
    }
}
