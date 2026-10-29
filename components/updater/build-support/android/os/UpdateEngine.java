package android.os;
import android.content.res.AssetFileDescriptor;
// Compile-only declarations verified against mica 16560795; never put in classes.dex.
public class UpdateEngine {
    public UpdateEngine() { throw new UnsupportedOperationException(); }
    public boolean bind(UpdateEngineCallback callback, Handler handler) { throw new UnsupportedOperationException(); }
    public boolean unbind() { throw new UnsupportedOperationException(); }
    public boolean verifyPayloadMetadata(String path) { throw new UnsupportedOperationException(); }
    public void applyPayload(AssetFileDescriptor fd, String[] properties) { throw new UnsupportedOperationException(); }
}
