package com.selcom.remote;
import android.util.Log;
public class CertUtils {
    private static final String TAG = "CertUtils";
    public static final String KEY_ALIAS = "SelcomRemoteKey";
    public static void ensureKeyExists() {
        Log.d(TAG, "Using hardcoded cert in RemoteProtocol - no keystore needed");
    }
}
