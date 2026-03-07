package com.selcom.remote;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

public class CertUtils {
    private static final String TAG = "CertUtils";
    public static final String KEY_ALIAS = "SelcomRemoteKey";

    public static void ensureKeyExists() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) { Log.d(TAG, "Key exists"); return; }
        Calendar s = Calendar.getInstance(), e = Calendar.getInstance();
        e.add(Calendar.YEAR, 25);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setKeySize(2048)
            .setCertificateSubject(new X500Principal("CN=SelcomRemote"))
            .setCertificateSerialNumber(BigInteger.ONE)
            .setCertificateNotBefore(s.getTime())
            .setCertificateNotAfter(e.getTime())
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .build());
        kpg.generateKeyPair();
        Log.d(TAG, "Key generated");
    }

    public static SSLContext createSSLContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        kmf.init(ks, null);
        TrustManager[] tm = { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tm, new SecureRandom());
        return ctx;
    }
}
