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
            + "f331790870eaa8e442f09dba93a502030100010282010009784eadb311e9cace0968c6b0fbb21f24"
            + "8f2e87e96ef9377406c2f59081cf040250e103b4c47297a94787d92bf2018e9037c261ed88d7ef96"
            + "5292d11055d5f59a67be59e1250aaf6ae3291e72bcecc9958e2565bb635ae43e24fe4fcaa482fd63"
            + "91807927f41131306cff13e86f6d2809298834de6d037889f364c610e29ed42084c4c51f33e119de"
            + "4114f73241f3c231cd27a74d34bfb88b36b25919c8d9ff585d9d7710ae799c3679eb7d95d16357ca"
            + "a3f510e5aa01e7a61baf5e982e225196c0cd7d7cc58975d3fbbb5f6077e3a1bb2364d2719b075d90"
            + "4f6fd267b3353ea7b2991c3d6af8e4fe58fc12786b4c84103adab168ba72d92c0eac96064fbf7902"
            + "818100ffbe83234a9a8feca20562e3ae6e8a95b8e096741339b340e6dc87ccf4ad20c32043a9a11a"
            + "fefa1682efdf35a0a98bd45ccb6e0fae85006fda1e5815d8ee3fc2e0ae154f4ab1aaad8db4c64a7e"
            + "77e9d3ed986a5e350fa368a374d0430f4340290de93860ce607f198c8027a65fdffd509dee6b5796"
            + "e899d9d8a6eccde81da41d02818100caad157f51af08ab580f4b6d8397bce860e6a592ee6db5d84c"
            + "2a150b89701c1712138293d4c1673c6938770b0c8e652c76a4fc3d2e8413d33411bb982686e311c0"
            + "ea332f323ff9b3353538a14c2ac7d932d1c606e9dc9e8ab58c5c4e180a6a32585386b58c06bb99b8"
            + "0910d7892e4ae2480b726833db845508a0556e1230872902818100c24c7c975073d34ae5e18fbb09"
            + "684473f1ecf781a2a5a0d17b542afc851c0f9b0fa5387804e99919874b34db2a8005934718eb3a90"
            + "cdcd822d4606883ab2efd060210261a68f0aec26902462ae68ee46abe9b34e75a3b6f3a5d3f6f22b"
            + "e35d1893d00f9c44cf3d612cc4a4db1b5632bf8fed76b22a1df7dd716388dffb2ca1e5028181009e"
            + "1ffa04b27b081d7e7fb84e81fb91b40f5e03d225d94ca5ab8ead8aa9b8e10192e5cbdb808340031e"
            + "e8a1dfe9f4f2b4850065976a423ba16d1f64a7e96f159b9552638aaffebfd6f46d4878778f6d0a65"
            + "1ecb0c3bcb179a8ad82e6ff34bb4dd00927228144e707116e763cf7544bbc1dd89a8c1e9ab9b8c28"
            + "45c7413049d2390281810099d5e2b7890b75218494a90c3579bbdffa2721a35fad52bd5168c525ea"
            + "1d300c9129cf5a9932144463d0d64746bd8dc27a334e5027875b2cf7d40852faf79bb724a3cc1cc2"
            + "fa6c312d1a08af28dc68653d656cfab994daa38ad373cdf9a7f272343f8730abffcf519744e2ba74"
            + "3f8a07326e614bc068182f4147e420d3594696";

    private static final String CERT_HEX =
            "308202b33082019ba0030201020213572f1ce3a87df8fe71b9213fa381f1a0d02e25300d06092a86"
            + "4886f70d01010b050030143112301006035504030c0961747672656d6f7465301e170d3233303130"
            + "313030303030305a170d3335303130313030303030305a30143112301006035504030c0961747672"
            + "656d6f746530820122300d06092a864886f70d01010105000382010f003082010a0282010100ca79"
            + "3cb2499677079b4bec0c41c29505b7133cbed5402ca235c2d29d6d2ab32b8f93b4ccd93d7a41c241"
            + "5cd3326579204804ba2206b43a1486645b6bafd0c10b48cb0253ef1f7e160df42ed1fdbc04f852fe"
            + "43589d44fcc59a96a925394c084286a96ada23ce3c7222b77c9eb98f82ae08b100c3a635a6a43004"
            + "3c812c0cc113abe2dc8bcee0bec2b9b4bd0a141df5284019940ceca75780363d8d10a084e7d93ee2"
            + "b716e751d407738ca8a47698a57f8504473605183e43594c1da43b062f1044ac5e50f394e527a6eb"
            + "876033634ad07f679e1a0879b63c1052f8103f42e31dbcfd9ccf9de1b642b50d611e7884b96fa80f"
            + "f331790870eaa8e442f09dba93a50203010001300d06092a864886f70d01010b0500038201010007"
            + "aee5f8804ef15b046869a94d65bd0ac48d4c4b094874997704dc1b3c069ab070787062ffd37c2b37"
            + "92d3f178f08314b925353f8a1db397427e062eeea7513ec03341cbdc7d7b15935580fad4739890c0"
            + "a147e19a9f3cdbd6029ca8ff424f038d7363a06584a58c4a0c7363dfb0c09a06a7e1b5d5a46f23d8"
            + "5c842582f2b28d879ecc2d1e12a85696d7e54d48b59b4a0f2fb1ad50887267f62d899e60aca8f55c"
            + "1cc175533558af8afd924ae0be17a199d00398457a0e674c80bfe07acba1504f60cbd8065dfdb759"
            + "058e8cab69b6042c3c71f73909d504d615d3786bd07f93b33e3d7333ce5f7d5b80f7610be1e9fe0b"
            + "69963ba758157b8088098f667ce1f8";

    // RemoteMessage { remote_configure { code1=615, device_info { unknown1=1, unknown2="1",
    //   package_name="atvremote", app_version="1.0.0" } } }
    // 615 = PING(1)|KEY(2)|IME(4)|POWER(32)|VOLUME(64)|APP_LINK(512) — matches tronikos default
    // code1 varint 615: 615 = 0x267 → [0xE7, 0x04]
    // outer len = 4 + device_info_len
    // device_info: unknown1(2) + unknown2(3) + pkg(11) + ver(7) = 23 bytes
    // device_info field: tag(0x12) + len(0x17) + 23 = 25 bytes
    // code1: tag(0x08) + varint615(0xE7,0x04) = 3 bytes
    // outer body = 3 + 25 = 28 bytes
    // outer: tag(0x0A) + len(0x1C=28) + 28 = 30 bytes total
    private static final byte[] CONFIGURE_RESPONSE = {
        0x0A, 0x1C,                          // field1 wire2, len=28
          0x08, (byte)0xE7, 0x04,            // code1 = 615 (varint)
          0x12, 0x17,                        // field2 wire2, len=23
            0x18, 0x01,                      // unknown1 = 1
            0x22, 0x01, 0x31,                // unknown2 = "1"
            0x2A, 0x09, 0x61,0x74,0x76,0x72,0x65,0x6D,0x6F,0x74,0x65, // "atvremote"
            0x32, 0x05, 0x31,0x2E,0x30,0x2E,0x30  // "1.0.0"
    };

    // RemoteMessage { remote_set_active { active=615 } }
    // field2 wire2: tag=0x12, len=3, inner: field1 varint 615 = [0x08, 0xE7, 0x04]
    private static final byte[] SET_ACTIVE_RESPONSE = {
        0x12, 0x03, 0x08, (byte)0xE7, 0x04
    };

    private SSLSocket sock;
    private InputStream in;
    private OutputStream out;
    private X509Certificate clientCert;
    private final Object outLock = new Object();

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
        in = sock.getInputStream();
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
        in = sock.getInputStream();
        out = sock.getOutputStream();
        Log.d(TAG, "Remote TLS OK");
        // Do NOT send anything — TV initiates the handshake
    }

    public void sendConfigureResponse() throws Exception {
        sendMsg(CONFIGURE_RESPONSE);
        Log.d(TAG, "-> ConfigureResponse (code1=615)");
    }

    public void sendSetActiveResponse() throws Exception {
        sendMsg(SET_ACTIVE_RESPONSE);
        Log.d(TAG, "-> SetActiveResponse (active=615)");
    }

    public synchronized void sendKeyCode(int kc) throws Exception {
        // RemoteMessage { remote_key_inject { key_code=kc, direction=SHORT(3) } }
        // remote_key_inject = field 10, tag=(10<<3)|2=82=0x52
        sendMsg(new byte[]{0x52, 0x04, 0x08, (byte) kc, 0x10, 0x03});
    }

    // Respond to remote_ping_request (field 8, tag=0x42) with remote_ping_response (field 9, tag=0x4A)
    public void sendPingResponse(int v) throws Exception {
        sendMsg(new byte[]{0x4A, 0x02, 0x08, (byte) v});
    }

    public byte[] readRemoteMessage() throws Exception { return readMsg(); }

    // Decode the field number from the first varint tag of a protobuf message.
    // Handles multi-byte tags correctly (e.g. field 40 = 2-byte varint).
    public int parseOuterFieldNumber(byte[] d) {
        if (d == null || d.length == 0) return -1;
        int tag = 0, shift = 0;
        for (int i = 0; i < d.length && i < 5; i++) {
            int b = d[i] & 0xFF;
            tag |= (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
        }
        return tag >>> 3;
    }

    // Parse val1 from remote_ping_request: skip outer tag varint, skip len byte, skip 0x08, read value
    public int parsePingValue(byte[] d) {
        int i = 0;
        while (i < d.length && (d[i] & 0x80) != 0) i++;
        i++; i++; i++; // past tag, len, inner tag
        return (i < d.length) ? (d[i] & 0x7F) : 0;
    }

    public boolean isConnected() { return sock != null && sock.isConnected() && !sock.isClosed(); }

    private void sendMsg(byte[] msg) throws Exception {
        synchronized (outLock) {
            out.write(msg.length & 0xFF);
            out.write(msg);
            out.flush();
        }
    }

    private byte[] readMsg() throws Exception {
        int len = in.read();
        if (len < 0) throw new EOFException("stream closed");
        byte[] buf = new byte[len];
        int r = 0;
        while (r < len) {
            int n = in.read(buf, r, len - r);
            if (n < 0) throw new EOFException("stream closed mid-msg");
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
