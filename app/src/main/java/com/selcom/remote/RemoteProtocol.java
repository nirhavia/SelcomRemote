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

public class RemoteProtocol implements Closeable {
    private static final String TAG = "RemoteProtocol";
    public  static final int PORT_PAIRING = 6467;
    public  static final int PORT_REMOTE  = 6466;

    private static final String KEY_B64 =
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKeTyySZZ3B5tL7AxBwpUF"
        + "txM8vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZkW2uv0MELSMsCU+8f"
        + "fhYN9C7R/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4KuCLEAw6Y1pqQwBDyB"
        + "LAzBE6vi3IvO4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR1AdzjKikdpilf4UE"
        + "RzYFGD5DWUwdpDsGLxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQP0LjHbz9nM+d4bZC"
        + "tQ1hHniEuW+oD/MxeQhw6qjkQvCdupOlAgMBAAECggEACXhOrbMR6crOCWjGsPuyHySPLofp"
        + "bvk3dAbC9ZCBzwQCUOEDtMRyl6lHh9kr8gGOkDfCYe2I1++WUpLREFXV9ZpnvlnhJQqvauMp"
        + "HnK87MmVjiVlu2Na5D4k/k/KpIL9Y5GAeSf0ETEwbP8T6G9tKAkpiDTebQN4ifNkxhDintQg"
        + "hMTFHzPhGd5BFPcyQfPCMc0np000v7iLNrJZGcjZ/1hdnXcQrnmcNnnrfZXRY1fKo/UQ5aoB"
        + "56Ybr16YLiJRlsDNfXzFiXXT+7tfYHfjobsjZNJxmwddkE9v0mezNT6nspkcPWr45P5Y/BJ4"
        + "a0yEEDrasWi6ctksDqyWBk+/eQKBgQD/voMjSpqP7KIFYuOuboqVuOCWdBM5s0Dm3IfM9K0g"
        + "wyBDqaEa/voWgu/fNaCpi9Rcy24ProUAb9oeWBXY7j/C4K4VT0qxqq2NtMZKfnfp0+2Yal41"
        + "D6Noo3TQQw9DQCkN6ThgzmB/GYyAJ6Zf3/1Qne5rV5bomdnYpuzN6B2kHQKBgQDKrRV/Ua8I"
        + "q1gPS22Dl7zoYOalku5ttdhMKhULiXAcFxITgpPUwWc8aTh3CwyOZSx2pPw9LoQT0zQRu5gm"
        + "huMRwOozLzI/+bM1NTihTCrH2TLRxgbp3J6KtYxcThgKajJYU4a1jAa7mbgJENeJLkriSAty"
        + "aDPbhFUIoFVuEjCHKQKBgQDCTHyXUHPTSuXhj7sJaERz8ez3gaKloNF7VCr8hRwPmw+lOHgE"
        + "6ZkZh0s02yqABZNHGOs6kM3Ngi1GBog6su/QYCECYaaPCuwmkCRirmjuRqvps051o7bzpdP2"
        + "8ivjXRiT0A+cRM89YSzEpNsbVjK/j+12siod991xY4jf+yyh5QKBgQCeH/oEsnsIHX5/uE6B"
        + "+5G0D14D0iXZTKWrjq2KqbjhAZLly9uAg0ADHuih3+n08rSFAGWXakI7oW0fZKfpbxWblVJj"
        + "iq/+v9b0bUh4d49tCmUeyww7yxeaitgub/NLtN0AknIoFE5wcRbnY891RLvB3Ymowemrm4wo"
        + "RcdBMEnSOQKBgQCZ1eK3iQt1IYSUqQw1ebvf+icho1+tUr1RaMUl6h0wDJEpz1qZMhREY9DW"
        + "R0a9jcJ6M05QJ4dbLPfUCFL695u3JKPMHML6bDEtGgivKNxoZT1lbPq5lNqjitNzzfmn8nI0"
        + "P4cwq//PUZdE4rp0P4oHMm5hS8BoGC9BR+Qg01lGlg==";
    private static final String CERT_B64 =
        "MIICszCCAZugAwIBAgITVy8c46h9+P5xuSE/o4HxoNAuJTANBgkqhkiG9w0BAQsFADAUMRIw"
        + "EAYDVQQDDAlhdHZyZW1vdGUwHhcNMjMwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAUMRIw"
        + "EAYDVQQDDAlhdHZyZW1vdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKeTyy"
        + "SZZ3B5tL7AxBwpUFtxM8vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZk"
        + "W2uv0MELSMsCU+8ffhYN9C7R/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4Ku"
        + "CLEAw6Y1pqQwBDyBLAzBE6vi3IvO4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR"
        + "1AdzjKikdpilf4UERzYFGD5DWUwdpDsGLxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQ"
        + "P0LjHbz9nM+d4bZCtQ1hHniEuW+oD/MxeQhw6qjkQvCdupOlAgMBAAEwDQYJKoZIhvcNAQEL"
        + "BQADggEBAAeu5fiATvFbBGhpqU1lvQrEjUxLCUh0mXcE3Bs8BpqwcHhwYv/TfCs3ktPxePCD"
        + "FLklNT+KHbOXQn4GLu6nUT7AM0HL3H17FZNVgPrUc5iQwKFH4ZqfPNvWApyo/0JPA41zY6Bl"
        + "hKWMSgxzY9+wwJoGp+G11aRvI9hchCWC8rKNh57MLR4SqFaW1+VNSLWbSg8vsa1QiHJn9i2J"
        + "nmCsqPVcHMF1UzVYr4r9kkrgvhehmdADmEV6DmdMgL/gesuhUE9gy9gGXf23WQWOjKtptgQs"
        + "PHH3OQnVBNYV03hr0H+Tsz49czPOX31bgPdhC+Hp/gtpljunWBV7gIgJj2Z84fg==";

    private SSLSocket sock;
    private InputStream  in;
    private OutputStream out;
    private X509Certificate clientCert;

    public RemoteProtocol() {}

    private SSLContext buildSSLContext() throws Exception {
        byte[] keyBytes  = Base64.decode(KEY_B64.replaceAll("\\s",""), Base64.DEFAULT);
        byte[] certBytes = Base64.decode(CERT_B64.replaceAll("\\s",""), Base64.DEFAULT);
        PrivateKey privKey = KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certBytes));
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

    private void openSocket(String host, int port, int timeoutMs) throws Exception {
        SSLContext ssl = buildSSLContext();
        sock = (SSLSocket) ssl.getSocketFactory().createSocket();
        sock.setEnabledProtocols(sock.getSupportedProtocols());
        sock.setEnabledCipherSuites(sock.getSupportedCipherSuites());
        sock.connect(new InetSocketAddress(host, port), timeoutMs);
        sock.setSoTimeout(60000);
        sock.startHandshake();
        in  = sock.getInputStream();
        out = sock.getOutputStream();
        Log.d(TAG, "Connected port=" + port + " tls=" + sock.getSession().getProtocol());
    }

    public void connectForPairing(String host) throws Exception { openSocket(host, PORT_PAIRING, 5000); }
    public void connectForRemote(String host)  throws Exception { openSocket(host, PORT_REMOTE,  5000); sock.setSoTimeout(35000); }

    // Step 1
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

    // Step 2 - exact bytes
    public void sendPairingOptions() throws Exception {
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)162,1,8,10,4,8,3,16,6,24,1});
        Log.d(TAG, "-> Options");
    }

    // Step 3 - exact bytes - TV shows code after ack
    public void sendPairingConfig() throws Exception {
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)242,1,8,10,4,8,3,16,6,16,1});
        Log.d(TAG, "-> Config");
    }

    public void readAndDiscard() throws Exception {
        byte[] d = readMsg();
        Log.d(TAG, "<- ack " + d.length + "b");
    }

    // Secret = SHA256(cMod+cExp+sMod+sExp + hexToBytes(last4ofPin))
    public boolean sendPairingSecret(String pin) throws Exception {
        X509Certificate srv = (X509Certificate) sock.getSession().getPeerCertificates()[0];
        RSAPublicKey cPub = (RSAPublicKey) clientCert.getPublicKey();
        RSAPublicKey sPub = (RSAPublicKey) srv.getPublicKey();
        String last4 = pin.substring(Math.max(0, pin.length()-4));
        byte[] pinBytes = hexToBytes(last4);
        Log.d(TAG, "secret pin=" + pin + " last4=" + last4);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(unsigned(cPub.getModulus()));
        sha.update(unsigned(cPub.getPublicExponent()));
        sha.update(unsigned(sPub.getModulus()));
        sha.update(unsigned(sPub.getPublicExponent()));
        sha.update(pinBytes);
        byte[] secret = sha.digest();
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(new byte[]{8,2,16,(byte)200,1,(byte)194,2,34,10,32});
        msg.write(secret);
        sendMsg(msg.toByteArray());
        Log.d(TAG, "-> Secret");
        byte[] ack = readMsg();
        boolean ok = ack.length >= 5 && (ack[3]&0xFF)==200;
        Log.d(TAG, "<- SecretAck ok=" + ok);
        return ok;
    }

    public synchronized void sendKeyCode(int kc) throws Exception {
        sendMsg(new byte[]{82, 5, 8, (byte)kc, 1, 16, 3});
    }

    public void sendPingResponse(int v) throws Exception {
        byte[] pong = new byte[]{74, 2, 8, (byte)v};
        out.write(pong); out.flush();
        Log.d(TAG, "-> pong");
    }

    public byte[] readRemoteMessage() throws Exception { return readMsg(); }

    public int parseOuterFieldNumber(byte[] d) {
        return d.length == 0 ? -1 : (d[0]&0xFF) >> 3;
    }

    public int parsePingValue(byte[] d) {
        return d.length >= 4 ? d[3]&0xFF : 0;
    }

    // 1-byte framing
    private void sendMsg(byte[] msg) throws Exception {
        out.write(msg.length & 0xFF);
        out.write(msg); out.flush();
    }

    private byte[] readMsg() throws Exception {
        int len = in.read() & 0xFF;
        byte[] buf = new byte[len]; int r = 0;
        while (r < len) { int n = in.read(buf, r, len-r); if (n<0) throw new EOFException(); r+=n; }
        return buf;
    }

    private static byte[] unsigned(java.math.BigInteger n) {
        byte[] b = n.abs().toByteArray();
        if (b[0]==0) { byte[] t=new byte[b.length-1]; System.arraycopy(b,1,t,0,t.length); return t; }
        return b;
    }
    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length()/2];
        for (int i=0; i<hex.length(); i+=2)
            out[i/2] = (byte) Integer.parseInt(hex.substring(i,i+2),16);
        return out;
    }

    public boolean isConnected() { return sock!=null && !sock.isClosed() && sock.isConnected(); }
    @Override public void close() { try { if (sock!=null) sock.close(); } catch (IOException ignored) {} }
}
