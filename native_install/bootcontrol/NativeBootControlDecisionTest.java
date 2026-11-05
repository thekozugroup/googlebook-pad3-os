public final class NativeBootControlDecisionTest {
    private static int checks;
    private static void reject(int active, int current, int count, int merge, boolean bootable, boolean successful, String suffix) {
        try { NativeBootControlProbe.guardReady(active,current,count,merge,bootable,successful,suffix); throw new AssertionError("Unsafe slot state accepted"); }
        catch (IllegalStateException expected) { checks++; }
    }
    public static void main(String[] args) {
        NativeBootControlProbe.guardReady(0,0,2,0,true,true,"_a"); checks++;
        NativeBootControlProbe.guardReady(1,1,2,0,true,true,"_b"); checks++;
        for (int merge : new int[]{-1,1,2,3,4,5}) reject(0,0,2,merge,true,true,"_a");
        reject(1,0,2,0,true,true,"_a"); reject(0,1,2,0,true,true,"_b");
        reject(0,0,1,0,true,true,"_a"); reject(0,0,3,0,true,true,"_a");
        reject(0,0,2,0,false,true,"_a"); reject(0,0,2,0,true,false,"_a");
        reject(0,0,2,0,true,true,"_b"); reject(0,0,2,0,true,true,"");
        reject(0,0,2,0,true,true,"_c"); reject(-1,-1,2,0,true,true,"_a");
        System.out.println("BOOT_CONTROL_DECISION_CHECKS_PASSED=" + checks);
    }
}
