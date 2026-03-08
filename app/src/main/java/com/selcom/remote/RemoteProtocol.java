package com.selcom.remote;

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
    public static final int PORT_PAIRING = 6467;
    public static final int PORT_REMOTE  = 6466;

    private static final String KEY_HEX =
            "308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100ca79"
            + "3cb2499677079b4bec0c41c29505b7133cbed5402ca235c2d29d6d2ab32b8f93b4ccd93d7a41c241"
            + "5cd3326579204804ba2206b43a1486645b6bafd0c10b48cb0253ef1f7e160df42ed1fdbc04f852fe"
            + "43589d44fcc59a96a925394c084286a96ada23ce3c7222b77c9eb98f82ae08b100c3a635a6a43004"
            + "3c812c0cc113abe2dc8bcee0bec2b9b4bd0a141df5284019940ceca75780363d8d10a084e7d93ee2"
            + "b716e751d407738ca8a47698a57f8504473605183e43594c1da43b062f1044ac5e50f394e527a6eb"
            + "876033634ad07f679e1a0879b63c1052f8103f42e31dbcfd9ccf9de1b642b50d611e7884b96fa80f"
            + "f331790870eaa8e442f09dba93a502030100010282010009784eadb311e9cace0968c6b0fbb21f24";

    private static final String CERT_HEX =
            "308202b33082019ba0030201020213572f1ce3a87df8fe71b9213fa381f1a0d02e25300d06092a86"
            + "4886f70d01010b050030143112301006035504030c0961747672656d6f7465301e170d3233303130"
            + "313030303030305a170d3335303130313030303030305a30143112301006035504030c0961747672"
            + "656d6f746530820122300d06092a864886f70d01010105000382010f003082010a0282010100ca79"
            + "3cb2499677079b4bec0c41c29505b7133cbed5402ca235c2d29d6d2ab32b8f93b4ccd93d7a41c241";

    private SSLSocket sock;
    private InputStream in;
    private OutputStream out;
    private X509Certificate clientCert;

    public RemoteProtocol() {}

    private static byte[] fromHex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < h.length(); i += 2)
            b[i / 2] = (byte) Integer.parseInt(h.substring(i, i + 2), 16);
        return b;
    }

    private SSLContext buildSSLContext() throws Exception {
        PrivateKey privKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(fromHex(KEY_HEX)));
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(fromHex(CERT_HEX)));
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

    public void readAndDiscard() throws Exception { readMsg(); }

    public boolean sendPairingSecret(String pin) throws Exception {
        X509Certificate srv = (X509Certificate) sock.getSession().getPeerCertificates()[0];
        RSAPublicKey cPub = (RSAPublicKey) clientCert.getPublicKey();
        RSAPublicKey sPub = (RSAPublicKey) srv.getPublicKey();
        String last4 = pin.substring(Math.max(0, pin.length() - 4));
        byte[] pinBytes = fromHex(last4);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(unsigned(cPub.getModulus()));   sha.update(unsigned(cPub.getPublicExponent()));
        sha.update(unsigned(sPub.getModulus()));   sha.update(unsigned(sPub.getPublicExponent()));
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

    public void connectForRemote(String host) throws Exception {
        SSLContext ssl = buildSSLContext();
        sock = (SSLSocket) ssl.getSocketFactory().createSocket();
        sock.setEnabledProtocols(sock.getSupportedProtocols());
        sock.setEnabledCipherSuites(sock.getSupportedCipherSuites());
        sock.connect(new InetSocketAddress(host, PORT_REMOTE), 5000);
        sock.startHandshake();
        in  = sock.getInputStream();
        out = sock.getOutputStream();
        Log.d(TAG, "Remote TLS OK");
    }

    public void sendRemoteStart() throws Exception {
        sendMsg(new byte[]{34, 2, 8, 1});
        Log.d(TAG, "-> RemoteStart");
    }

    public synchronized void sendKeyCode(int kc) throws Exception {
        sendMsg(new byte[]{34, 4, 8, (byte) kc, 16, 3});
    }

    public void sendKeepalive() throws Exception {
        out.write(new byte[]{48, 1});
        out.flush();
    }

    public void sendPingResponse(int v) throws Exception {
        out.write(new byte[]{74, 2, 8, (byte) v});
        out.flush();
    }

    public byte[] readRemoteMessage() throws Exception { return readMsg(); }
    public int parseOuterFieldNumber(byte[] d) { return d.length == 0 ? -1 : (d[0] & 0xFF) >> 3; }
    public int parsePingValue(byte[] d) { return d.length >= 4 ? d[3] & 0xFF : 0; }
    public boolean isConnected() { return sock != null && sock.isConnected() && !sock.isClosed(); }

    private void sendMsg(byte[] msg) throws Exception {
        out.write(msg.length & 0xFF);
        out.write(msg);
        out.flush();
    }

    private byte[] readMsg() throws Exception {
        int len = in.read() & 0xFF;
        byte[] buf = new byte[len]; int r = 0;
        while (r < len) {
            int n = in.read(buf, r, len - r);
            if (n < 0) throw new EOFException();
            r += n;
        }
        return buf;
    }

    private static byte[] unsigned(java.math.BigInteger n) {
        byte[] b = n.abs().toByteArray();
        if (b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            return t;
        }
        return b;
    }

    @Override public void close() {
        try { if (sock != null) sock.close(); } catch (IOException ignored) {}
    }
}
