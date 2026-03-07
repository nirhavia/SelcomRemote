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
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKeTyySZZ3B5tL7AxBwpUFtxM8"
        + "vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZkW2uv0MELSMsCU+8ffhYN9C7R"
        + "/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4KuCLEAw6Y1pqQwBDyBLAzBE6vi3IvO"
        + "4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR1AdzjKikdpilf4UERzYFGD5DWUwdpDsG"
        + "LxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQP0LjHbz9nM+d4bZCtQ1hHniEuW+oD/MxeQhw"
        + "6qjkQvCdupOlAgMBAAECggEACXhOrbMR6crOCWjGsPuyHySPLofpbvk3dAbC9ZCBzwQCUOEDtMRy"
        + "l6lHh9kr8gGOkDfCYe2I1++WUpLREFXV9ZpnvlnhJQqvauMpHnK87MmVjiVlu2Na5D4k/k/KpIL9"
        + "Y5GAeSf0ETEwbP8T6G9tKAkpiDTebQN4ifNkxhDintQghMTFHzPhGd5BFPcyQfPCMc0np000v7iL"
        + "NrJZGcjZ/1hdnXcQrnmcNnnrfZXRY1fKo/UQ5aoB56Ybr16YLiJRlsDNfXzFiXXT+7tfYHfjobsj"
        + "ZNJxmwddkE9v0mezNT6nspkcPWr45P5Y/BJ4a0yEEDrasWi6ctksDqyWBk+/eQKBgQD/voMjSpqP"
        + "7KIFYuOuboqVuOCWdBM5s0Dm3IfM9K0gwyBDqaEa/voWgu/fNaCpi9Rcy24ProUAb9oeWBXY7j/C"
        + "4K4VT0qxqq2NtMZKfnfp0+2Yal41D6Noo3TQQw9DQCkN6ThgzmB/GYyAJ6Zf3/1Qne5rV5bomdnY"
        + "puzN6B2kHQKBgQDKrRV/Ua8Iq1gPS22Dl7zoYOalku5ttdhMKhULiXAcFxITgpPUwWc8aTh3CwyO"
        + "ZSx2pPw9LoQT0zQRu5gmhuMRwOozLzI/+bM1NTihTCrH2TLRxgbp3J6KtYxcThgKajJYU4a1jAa7"
        + "mbgJENeJLkriSAtyaDPbhFUIoFVuEjCHKQKBgQDCTHyXUHPTSuXhj7sJaERz8ez3gaKloNF7VCr8"
        + "hRwPmw+lOHgE6ZkZh0s02yqABZNHGOs6kM3Ngi1GBog6su/QYCECYaaPCuwmkCRirmjuRqvps051"
        + "o7bzpdP28ivjXRiT0A+cRM89YSzEpNsbVjK/j+12siod991xY4jf+yyh5QKBgQCeH/oEsnsIHX5/"
        + "uE6B+5G0D14D0iXZTKWrjq2KqbjhAZLly9uAg0ADHuih3+n08rSFAGWXakI7oW0fZKfpbxWblVJj"
        + "iq/+v9b0bUh4d49tCmUeyww7yxeaitgub/NLtN0AknIoFE5wcRbnY891RLvB3Ymowemrm4woRcdB"
        + "MEnSOQKBgQCZ1eK3iQt1IYSUqQw1ebvf+icho1+tUr1RaMUl6h0wDJEpz1qZMhREY9DWR0a9jcJ6"
        + "M05QJ4dbLPfUCFL695u3JKPMHML6bDEtGgivKNxoZT1lbPq5lNqjitNzzfmn8nI0P4cwq//PUZdE"
        + "4rp0P4oHMm5hS8BoGC9BR+Qg01lGlg==";

    private static final String CERT_B64 =
        "MIICszCCAZugAwIBAgITVy8c46h9+P5xuSE/o4HxoNAuJTANBgkqhkiG9w0BAQsFADAUMRIwEAYD"
        + "VQQDDAlhdHZyZW1vdGUwHhcNMjMwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAUMRIwEAYDVQQD"
        + "DAlhdHZyZW1vdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKeTyySZZ3B5tL7AxB"
        + "wpUFtxM8vtVALKI1wtKdbSqzK4+TtMzZPXpBwkFc0zJleSBIBLoiBrQ6FIZkW2uv0MELSMsCU+8f"
        + "fhYN9C7R/bwE+FL+Q1idRPzFmpapJTlMCEKGqWraI848ciK3fJ65j4KuCLEAw6Y1pqQwBDyBLAzB"
        + "E6vi3IvO4L7CubS9ChQd9ShAGZQM7KdXgDY9jRCghOfZPuK3FudR1AdzjKikdpilf4UERzYFGD5D"
        + "WUwdpDsGLxBErF5Q85TlJ6brh2AzY0rQf2eeGgh5tjwQUvgQP0LjHbz9nM+d4bZCtQ1hHniEuW+o"
        + "D/MxeQhw6qjkQvCdupOlAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAeu5fiATvFbBGhpqU1lvQrE"
        + "jUxLCUh0mXcE3Bs8BpqwcHhwYv/TfCs3ktPxePCDFLklNT+KHbOXQn4GLu6nUT7AM0HL3H17FZNV"
        + "gPrUc5iQwKFH4ZqfPNvWApyo/0JPA41zY6BlhKWMSgxzY9+wwJoGp+G11aRvI9hchCWC8rKNh57M"
        + "LR4SqFaW1+VNSLWbSg8vsa1QiHJn9i2JnmCsqPVcHMF1UzVYr4r9kkrgvhehmdADmEV6DmdMgL/g"
        + "esuhUE9gy9gGXf23WQWOjKtptgQsPHH3OQnVBNYV03hr0H+Tsz49czPOX31bgPdhC+Hp/gtpljun"
        + "WBV7gIgJj2Z84fg=";

    private SSLSocket sock;
    private InputStream  in;
    private OutputStream out;
    private X509Certificate clientCert;

    public RemoteProtocol() {}

    private SSLContext buildSSLContext() throws Exception {
        PrivateKey privKey = KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(KEY_B64, Base64.DEFAULT)));
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(Base64.decode(CERT_B64, Base64.DEFAULT)));
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
        Log.d(TAG, "Pairing TLS OK");
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
        Log.d(TAG, "Remote TLS OK");
    }

    public void sendPairingRequest() throws Exception {
        byte[] svc = "atvremote".getBytes("UTF-8");
        byte[] cli = "SelcomRemote".getBytes("UTF-8");
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.write(0x0A); inner.write(svc.length); inner.write(svc);
        inner.write(0x12); inner.write(cli.length); inner.write(cli);
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(new byte[]{8, 2, 16, (byte)200, 1, 82});
        msg.write(inner.size()); msg.write(inner.toByteArray());
        sendMsg(msg.toByteArray());
    }

    public void sendPairingOptions() throws Exception {
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)162,1,8,10,4,8,3,16,6,24,1});
    }

    public void sendPairingConfig() throws Exception {
        sendMsg(new byte[]{8,2,16,(byte)200,1,(byte)242,1,8,10,4,8,3,16,6,16,1});
    }

    public void readAndDiscard() throws Exception {
        readMsg();
    }

    public boolean sendPairingSecret(String pin) throws Exception {
        X509Certificate srv = (X509Certificate) sock.getSession().getPeerCertificates()[0];
        RSAPublicKey cPub = (RSAPublicKey) clientCert.getPublicKey();
        RSAPublicKey sPub = (RSAPublicKey) srv.getPublicKey();
        String last4 = pin.substring(Math.max(0, pin.length() - 4));
        byte[] pinBytes = hexToBytes(last4);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(unsigned(cPub.getModulus())); sha.update(unsigned(cPub.getPublicExponent()));
        sha.update(unsigned(sPub.getModulus())); sha.update(unsigned(sPub.getPublicExponent()));
        sha.update(pinBytes);
        byte[] secret = sha.digest();
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(new byte[]{8,2,16,(byte)200,1,(byte)194,2,34,10,32});
        msg.write(secret);
        sendMsg(msg.toByteArray());
        byte[] ack = readMsg();
        boolean ok = ack.length >= 5 && (ack[3] & 0xFF) == 200;
        Log.d(TAG, "SecretAck ok=" + ok);
        return ok;
    }

    // RemoteStart: field4 wire2, must send before key events
    public void sendRemoteStart() throws Exception {
        sendMsg(new byte[]{34, 2, 8, 1});
        Log.d(TAG, "-> RemoteStart");
    }

    // key_inject: field4 wire2 tag=34, action=PRESS(3)
    // wire: [6, 34, 4, 8, kc, 16, 3]
    public synchronized void sendKeyCode(int kc) throws Exception {
        sendMsg(new byte[]{34, 4, 8, (byte)kc, 16, 3});
    }

    // keepalive: field6 varint, NO length prefix
    public void sendKeepalive() throws Exception {
        out.write(new byte[]{48, 1}); out.flush();
    }

    // pong: NO length prefix
    public void sendPingResponse(int v) throws Exception {
        out.write(new byte[]{74, 2, 8, (byte)v}); out.flush();
    }

    public byte[] readRemoteMessage() throws Exception { return readMsg(); }
    public int parseOuterFieldNumber(byte[] d) { return d.length==0 ? -1 : (d[0]&0xFF)>>3; }
    public int parsePingValue(byte[] d) { return d.length>=4 ? d[3]&0xFF : 0; }
    public boolean isConnected() { return sock!=null && !sock.isClosed() && sock.isConnected(); }

    private void sendMsg(byte[] msg) throws Exception {
        out.write(msg.length & 0xFF); out.write(msg); out.flush();
    }
    private byte[] readMsg() throws Exception {
        int len = in.read() & 0xFF;
        byte[] buf = new byte[len]; int r = 0;
        while (r<len) { int n=in.read(buf,r,len-r); if(n<0) throw new EOFException(); r+=n; }
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
            out[i/2]=(byte)Integer.parseInt(hex.substring(i,i+2),16);
        return out;
    }
    @Override public void close() {
        try { if (sock!=null) sock.close(); } catch (IOException ignored) {}
    }
}