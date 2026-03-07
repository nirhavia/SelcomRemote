package com.selcom.remote;
import android.util.Log;

// CertUtils is no longer needed for key management.
// Keys are hardcoded in RemoteProtocol (PKCS12, identical to YES Remote).
// Kept as empty stub so other files that import it still compile.
public class CertUtils {
    private static final String TAG = "CertUtils";
    public static final String KEY_ALIAS = "SelcomRemoteKey"; // unused, kept for compat

    public static void ensureKeyExists() {
        Log.d(TAG, "Using hardcoded cert - no keystore needed");
    }
}
