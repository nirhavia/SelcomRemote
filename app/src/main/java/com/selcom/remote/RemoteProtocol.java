package com.selcom.remote;
import android.util.Base64;
import android.util.Log;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.ssl.*;

/**
 * Android TV Remote Protocol v2
 * Pairing port: 6467   Remote port: 6466
 * Framing: single-byte length prefix
 * Cert: hardcoded PKCS12 (same as YES Remote - works!)
 */
public class RemoteProtocol implements Closeable {
    private static final String TAG = "RemoteProtocol";
    public  static final int PORT_PAIRING = 6467;
    public  static final int PORT_REMOTE  = 6466;

    // Hardcoded RSA key+cert (identical to nirhavia/Remote - confirmed working)
    private static final String KEY_B64 =
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKeTyySZZ3B5tL7AxBwpUFtxM8vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZkW2uv0MELSMsCU+8ffhYN9C7R/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4KuCLEAw6Y1pqQwBDyBLAzBE6vi3IvO4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR1AdzjKikdpilf4UERzYFGD5DWUwdpDsGLxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQP0LjHbz9nM+d4bZCtQ1hHniEuW+oD/MxeQhw6qjkQvCdupOlAgMBAAECggEACXhOrbMR6crOCWjGsPuyHySPLofpbvk3dAbC9ZCBzwQCUOEDtMRyl6lHh9kr8gGOkDfCYe2I1++WUpLREFXV9ZpnvlnhJQqvauMpHnK87MmVjiVlu2Na5D4k/k/KpIL9Y5GAeSf0ETEwbP8T6G9tKAkpiDTebQN4ifNkxhDintQghMTFHzPhGd5BFPcyQfPCMc0np000v7iLNrJZGcjZ/1hdnXcQrnmcNnnrfZXRY1fKo/UQ5aoB56Ybr16YLiJRlsDNfXzFiXXT+7tfYHfjobsjZNJxmwddkE9v0mezNT6nspkcPWr45P5Y/BJ4a0yEEDrasWi6ctksDqyWBk+/eQKBgQD/voMjSpqP7KIFYuOuboqVuOCWdBM5s0Dm3IfM9K0gwyBDqaEa/voWgu/fNaCpi9Rcy24ProUAb9oeWBXY7j/C4K4VT0qxqq2NtMZKfnfp0+2Yal41D6Noo3TQQw9DQCkN6ThgzmB/GYyAJ6Zf3/1Qne5rV5bomdnYpuzN6B2kHQKBgQDKrRV/Ua8Iq1gPS22Dl7zoYOalku5ttdhMKhULiXAcFxITgpPUwWc8aTh3CwyOZSx2pPw9LoQT0zQRu5gmhuMRwOozLzI/+bM1NTihTCrH2TLRxgbp3J6KtYxcThgKajJYU4a1jAa7mbgJENeJLkriSAtyaDPbhFUIoFVuEjCHKQKBgQDCTHyXUHPTSuXhj7sJaERz8ez3gaKloNF7VCr8hRwPmw+lOHgE6ZkZh0s02yqABZNHGOs6kM3Ngi1GBog6su/QYCECYaaPCuwmkCRirmjuRqvps051o7bzpdP28ivjXRiT0A+cRM89YSzEpNsbVjK/j+12siod991xY4jf+yyh5QKBgQCeH/oEsnsIHX5/uE6B+5G0D14D0iXZTKWrjq2KqbjhAZLly9uAg0ADHuih3+n08rSFAGWXakI7oW0fZKfpbxWblVJjiq/+v9b0bUh4d49tCmUeyww7yxeaitgub/NLtN0AknIoFE5wcRbnY891RLvB3Ymowemrm4woRcdBMEnSOQKBgQCZ1eK3iQt1IYSUqQw1ebvf+icho1+tUr1RaMUl6h0wDJEpz1qZMhREY9DWR0a9jcJ6M05QJ4dbLPfUCFL695u3JKPMHML6bDEtGgivKNxoZT1lbPq5lNqjitNzzfmn8nI0P4cwq//PUZdE4rp0P4oHMm5hS8BoGC9BR+Qg01lGlg==";
    private static final String CERT_B64 =
        "MIICszCCAZugAwIBAgITVy8c46h9+P5xuSE/o4HxoNAuJTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlhdHZyZW1vdGUwHhcNMjMwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlhdHZyZW1vdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKeTyySZZ3B5tL7AxBwpUFtxM8vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZkW2uv0MELSMsCU+8ffhYN9C7R/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4KuCLEAw6Y1pqQwBDyBLAzBE6vi3IvO4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR1AdzjKikdpilf4UERzYFGD5DWUwdpDsGLxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQP0LjHbz9nM+d4bZCtQ1hHniEuW+oD/MxeQhw6qjkQvCdupOlAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAeu5fiATvFbBGhpqU1lvQrEjUxLCUh0mXcE3Bs8BpqwcHhwYv/TfCs3ktPxePCDFLklNT+KHbOXQn4GLu6nUT7AM0HL3H17FZNVgPrUc5iQwKFH4ZqfPNvWApyo/0JPA41zY6BlhKWMSgxzY9+wwJoGp+G11aRvI9hchCWC8rKNh57MLR4SqFaW1+VNSLWbSg8vsa1QiHJn9i2JnmCsqPVcHMF1UzVYr4r9kkrgvhehmdADmEV6DmdMgL/gesuhUE9gy9gGXf23WQWOjKtptgQsPHH3OQnVBNYV03hr0H+Tsz49czPOX31bgPdhC+Hp/gtpljunWBV7gIgJj2Z84fg==";

    private SSLSocket sock;
    private InputStream  in;
    private OutputStream out;
    private X509Certificate clientCert;

    // ── Connect ──────────────────────────────────────────────────────────────
    private SSLContext buildSSLContext() throws Exception {
        PrivateKey privKey = KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(KEY_B64, Base64.DEFAULT)));
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(Base64.decode(CERT_B64, Base64.DEFAULT)));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", privKey, new char[0], new X509Certificate[]{clientCert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        return ssl;
    }

    public void connectForPairing(String host) throws Exception {
        SSLContext ssl = buildSSLContext();
        sock = (SSLSocket) ssl.getSocketFactory().createSocket();
        sock.setEnabledProtocols(sock.getSupportedProtocols());
        sock.setEnabledCipherSuites(sock.getSupportedCipherSuites());
        sock.connect(new InetSocketAddress(host, PORT_PAIRING), 5000);
        sock.startHandshake();
        in  = sock.getInputStream();
        out = sock.getOutputStream();
        Log.d(TAG, "Pairing TLS OK: " + sock.getSession().getProtocol());
    }

    public void connectForRemote(String host) throws Exception {
        SSLContext ssl = buildSSLContext();
        sock = (SSLSocket) ssl.getSocketFactory().createSocket();
        sock.setEnabledProtocols(sock.getSupportedProtocols());
        sock.setEnabledCipherSuites(sock.getSupportedCipherSuites());
        sock.connect(new InetSocketAddress(host, PORT_REMOTE), 5000);
        sock.setSoTimeout(35000);
        sock.startHandshake();
        in  = sock.getInputStream();
        out = sock.getOutputStream();
        Log.d(TAG, "Remote TLS OK: " + sock.getSession().getProtocol());
    }

    // ── Pairing Steps ────────────────────────────────────────────────────────

    public void sendPairingRequest() throws Exception {
        byte[] svc = "atvremote".getBytes("UTF-8");
        byte[] cli = "SelcomRemote".getBytes("UTF-8");
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.write(0x0A); inner.write(svc.length); inner.write(svc);
        inner.write(0x12); inner.write(cli.length); inner.write(cli);
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(new byte[]{8, 2, 16, (byte)200, 1, 82});
        msg.write(inner.size());
        msg.write(inner.toByteArray());
        sendMsg(msg.toByteArray());
        Log.d(TAG, "-> PairingRequest");
    }

    public void sendPairingOptions() throws Exception {
        // Exact bytes from documentation
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)162,1,8,10,4,8,3,16,6,24,1});
        Log.d(TAG, "-> PairingOptions");
    }

    public void sendPairingConfig() throws Exception {
        // Exact bytes from documentation - TV shows code after ack
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)242,1,8,10,4,8,3,16,6,16,1});
        Log.d(TAG, "-> PairingConfig (TV will show code)");
    }

    public void readAndDiscard() throws Exception {
        byte[] d = readMsg();
        Log.d(TAG, "<- ack " + d.length + " bytes");
    }

    // Secret = SHA256(clientMod+clientExp+serverMod+serverExp + hexToBytes(last4ofPin))
    public boolean sendPairingSecret(String pin) throws Exception {
        X509Certificate srv = (X509Certificate) sock.getSession().getPeerCertificates()[0];
        RSAPublicKey cPub = (RSAPublicKey) clientCert.getPublicKey();
        RSAPublicKey sPub = (RSAPublicKey) srv.getPublicKey();

        byte[] cMod = unsigned(cPub.getModulus());
        byte[] cExp = unsigned(cPub.getPublicExponent());
        byte[] sMod = unsigned(sPub.getModulus());
        byte[] sExp = unsigned(sPub.getPublicExponent());

        // Last 4 chars of PIN (6-char hex → take last 4 → decode hex → 2 bytes)
        String last4 = pin.substring(Math.max(0, pin.length() - 4));
        byte[] pinBytes = hexToBytes(last4);
        Log.d(TAG, "Secret: pin=" + pin + " last4=" + last4);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(cMod); sha.update(cExp);
        sha.update(sMod); sha.update(sExp);
        sha.update(pinBytes);
        byte[] secret = sha.digest();

        // Exact format: [8,2,16,200,1,194,2,34,10,32] + 32 bytes secret
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(new byte[]{8,2,16,(byte)200,1,(byte)194,2,34,10,32});
        msg.write(secret);
        sendMsg(msg.toByteArray());
        Log.d(TAG, "-> PairingSecret");

        byte[] ack = readMsg();
        // Status OK = field2=200 → byte pattern [16,200,1]
        boolean ok = ack.length >= 5 && (ack[2] & 0xFF) == 16 && (ack[3] & 0xFF) == 200;
        Log.d(TAG, "<- SecretAck len=" + ack.length + " ok=" + ok);
        return ok;
    }

    // ── Remote Control ────────────────────────────────────────────────────────
    public synchronized void sendKeyCode(int kc) throws Exception {
        // [82,4,8,kc,16,3] for short press (DIR_SHORT=4 maps to action 3)
        sendMsg(new byte[]{82, 5, 8, (byte)kc, 1, 16, 3});
    }

    public void sendPingResponse(int v) throws Exception {
        // Pong: NO size prefix per docs
        byte[] pong = new byte[]{74, 2, 8, (byte)v};
        out.write(pong);
        out.flush();
        Log.d(TAG, "-> pong");
    }

    public byte[] readRemoteMessage() throws Exception { return readMsg(); }

    public int parseOuterFieldNumber(byte[] data) {
        if (data.length == 0) return -1;
        return (data[0] & 0xFF) >> 3;
    }

    public int parsePingValue(byte[] data) {
        // ping starts with [66,6,...] → inner value at byte 4
        if (data.length >= 4) return data[3] & 0xFF;
        return 0;
    }

    // ── Framing: single-byte length prefix ───────────────────────────────────
    private void sendMsg(byte[] msg) throws Exception {
        out.write(msg.length & 0xFF);   // single byte!
        out.write(msg);
        out.flush();
        Log.d(TAG, "Sent " + msg.length + " bytes");
    }

    private byte[] readMsg() throws Exception {
        int len = in.read() & 0xFF;
        byte[] buf = new byte[len]; int r = 0;
        while (r < len) { int n = in.read(buf, r, len - r); if (n < 0) throw new EOFException(); r += n; }
        return buf;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static byte[] unsigned(java.math.BigInteger n) {
        byte[] b = n.abs().toByteArray();
        if (b[0] == 0) { byte[] t = new byte[b.length-1]; System.arraycopy(b,1,t,0,t.length); return t; }
        return b;
    }
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i/2] = (byte) Integer.parseInt(hex.substring(i, i+2), 16);
        return out;
    }

    public boolean isConnected() { return sock != null && !sock.isClosed() && sock.isConnected(); }

    @Override public void close() {
        try { if (sock != null) sock.close(); } catch (IOException ignored) {}
    }
}
