import android.os.IBinder;
import android.os.Parcel;
import org.json.JSONArray;
import org.json.JSONObject;

/** Read-only frozen android.hardware.boot v1 AIDL probe. No installation API. */
public final class NativeBootControlProbe {
    private static final String DESCRIPTOR = "android.hardware.boot.IBootControl";
    private static final String SERVICE = DESCRIPTOR + "/default";

    private static Object read(IBinder service, int code, Integer slot, boolean stringResult) throws Exception {
        // IDs 1..7 were checked against SDK-generated bindings from frozen v1 AIDL.
        if (code < 1 || code > 7) throw new IllegalArgumentException("Only getter transactions are allowed");
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(DESCRIPTOR);
            if (slot != null) request.writeInt(slot.intValue());
            if (!service.transact(code, request, reply, 0)) throw new IllegalStateException("Getter not implemented: " + code);
            reply.readException();
            return stringResult ? reply.readString() : Integer.valueOf(reply.readInt());
        } finally {
            request.recycle();
            reply.recycle();
        }
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 0) throw new IllegalArgumentException("No arguments accepted");
        IBinder service = (IBinder) Class.forName("android.os.ServiceManager")
                .getMethod("checkService", String.class).invoke(null, SERVICE);
        if (service == null || !DESCRIPTOR.equals(service.getInterfaceDescriptor()))
            throw new IllegalStateException("AIDL BootControl service unavailable or wrong descriptor");
        int active = (Integer) read(service, 1, null, false);
        int current = (Integer) read(service, 2, null, false);
        int count = (Integer) read(service, 3, null, false);
        int merge = (Integer) read(service, 4, null, false);
        if (count != 2 || current < 0 || current >= count || active < 0 || active >= count)
            throw new IllegalStateException("Unreviewed slot count/state");
        String[] mergeNames = {"NONE", "UNKNOWN", "SNAPSHOTTED", "MERGING", "CANCELLED"};
        JSONObject output = new JSONObject().put("service", SERVICE).put("read_only", true)
                .put("active_slot", active).put("current_slot", current).put("slot_count", count)
                .put("snapshot_merge_status", merge)
                .put("snapshot_merge_name", merge >= 0 && merge < mergeNames.length ? mergeNames[merge] : "UNRECOGNIZED");
        JSONArray slots = new JSONArray();
        for (int slot = 0; slot < count; slot++) {
            slots.put(new JSONObject().put("slot", slot).put("suffix", read(service, 5, slot, true))
                    .put("bootable", ((Integer) read(service, 6, slot, false)).intValue() != 0)
                    .put("successful", ((Integer) read(service, 7, slot, false)).intValue() != 0));
        }
        output.put("slots", slots);
        System.out.println(output.toString(2));
    }
}
