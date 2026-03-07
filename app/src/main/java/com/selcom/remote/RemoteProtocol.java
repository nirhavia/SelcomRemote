package com.selcom.remote;
import android.util.Log;
import java.io.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import javax.net.ssl.*;

public class RemoteProtocol implements Closeable {
    private static final String TAG = "RemoteProtocol";
    public static final int PORT_PAIRING = 6467;
    public static final int PORT_REMOTE  = 6466;
    private static final int STATUS_OK   = 200;
    public  static final int DIR_SHORT   = 4;
    private static final int FLD_PING    = 1;
    private static final int FLD_PONG    = 2;
    private static final int FLD_ACTIVE  = 3;
    private static final int FLD_KEY     = 4;

    private SSLSocket socket;
    private InputStream  in;
    private OutputStream out;
    private final SSLContext sslContext;

    public RemoteProtocol(SSLContext ctx) { this.sslContext = ctx; }

    public void connectForPairing(String host) throws IOException { connect(host, PORT_PAIRING, 15000); }
    public void connectForRemote(String host)  throws IOException { connect(host, PORT_REMOTE,  35000); }

    private void connect(String host, int port, int timeout) throws IOException {
        Log.d(TAG, "Connecting " + host + ":" + port);
        SSLSocketFactory f = sslContext.getSocketFactory();
        socket = (SSLSocket) f.createSocket(host, port);
        socket.setSoTimeout(timeout);
        socket.startHandshake();
        in  = socket.getInputStream();
        out = socket.getOutputStream();
        Log.d(TAG, "Connected");
    }

    // ── Pairing ────────────────────────────────────────────────────────────

    // Step 1: send PairingRequest
    // PairingMessage { status(1)=200, pairing_request(10)={ service_name(1), client_name(2) } }
    public void sendPairingRequest(String serviceName, String clientName) throws IOException {
        byte[] inner = msg(strField(1, serviceName), strField(2, clientName));
        sendFramed(msg(varintField(1, STATUS_OK), lenField(10, inner)));
        Log.d(TAG, "Sent PairingRequest");
    }

    // Read and discard any incoming PairingMessage
    public void readAndDiscard() throws IOException {
        byte[] d = readFramed();
        Log.d(TAG, "Got pairing msg len=" + d.length);
    }

    // Step 3: send PairingOptions → TV will show the code on screen
    // PairingMessage { status(1)=200, options(20)={ preferred_encodings(1)={ type(3)=3, symbol_length(4)=6 }, preferred_role(2)=1 } }
    public void sendPairingOptions() throws IOException {
        byte[] enc    = msg(varintField(3, 3), varintField(4, 6));   // HEXADECIMAL, 6 chars
        byte[] optMsg = msg(lenField(1, enc),  varintField(2, 1));   // role=INPUT
        sendFramed(msg(varintField(1, STATUS_OK), lenField(20, optMsg)));
        Log.d(TAG, "Sent PairingOptions");
    }

    // Step 5: send secret
    // IMPORTANT: code is hex → convert to bytes BEFORE SHA256
    // secret = SHA256( client_cert_DER + server_cert_DER + hexToBytes(code) )
    public boolean sendPairingSecret(String hexCode) throws Exception {
        Certificate[] lc = socket.getSession().getLocalCertificates();
        Certificate[] sc = socket.getSession().getPeerCertificates();
        if (lc == null || lc.length == 0) throw new Exception("No local cert");

        byte[] codeBytes = hexStringToBytes(hexCode);
        Log.d(TAG, "Code bytes len=" + codeBytes.length + " from code=" + hexCode);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(lc[0].getEncoded());
        sha.update(sc[0].getEncoded());
        sha.update(codeBytes);
        byte[] secret = sha.digest();

        // PairingMessage { status(1)=200, secret(40)={ secret(1)=bytes } }
        sendFramed(msg(varintField(1, STATUS_OK), lenField(40, lenField(1, secret))));
        Log.d(TAG, "Sent PairingSecret");

        byte[] ack = readFramed();
        long status = parseVarintField(ack, 1);
        Log.d(TAG, "SecretAck status=" + status);
        return status == STATUS_OK;
    }

    // Convert hex string like "A1B2C3" → byte[] { 0xA1, 0xB2, 0xC3 }
    private static byte[] hexStringToBytes(String hex) {
        if (hex.length() % 2 != 0) hex = "0" + hex;
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    // ── Remote ────────────────────────────────────────────────────────────

    public void sendSetActive(boolean active) throws IOException {
        sendFramed(msg(lenField(FLD_ACTIVE, msg(varintField(1, active ? 1 : 0)))));
    }

    public synchronized void sendKeyCode(int kc) throws IOException {
        sendFramed(msg(lenField(FLD_KEY, msg(varintField(1, kc), varintField(2, DIR_SHORT)))));
    }

    public void sendPingResponse(int v) throws IOException {
        sendFramed(msg(lenField(FLD_PONG, msg(varintField(1, v)))));
    }

    public byte[] readRemoteMessage() throws IOException { return readFramed(); }

    public int parseOuterFieldNumber(byte[] data) {
        if (data.length == 0) return -1;
        long tag = 0; int shift = 0;
        for (byte b : data) { tag |= ((long)(b & 0x7F)) << shift; shift += 7; if ((b & 0x80) == 0) break; }
        return (int)(tag >> 3);
    }

    public int parsePingValue(byte[] data) {
        byte[] inner = parseEmbedded(data, FLD_PING);
        return inner == null ? 0 : (int) parseVarintField(inner, 1);
    }

    // ── Framing ───────────────────────────────────────────────────────────

    private void sendFramed(byte[] data) throws IOException {
        byte[] f = new byte[2 + data.length];
        f[0] = (byte)((data.length >> 8) & 0xFF);
        f[1] = (byte)(data.length & 0xFF);
        System.arraycopy(data, 0, f, 2, data.length);
        out.write(f); out.flush();
    }

    private byte[] readFramed() throws IOException {
        byte[] lb = new byte[2]; int r = 0;
        while (r < 2) { int n = in.read(lb, r, 2-r); if (n < 0) throw new EOFException(); r += n; }
        int len = ((lb[0] & 0xFF) << 8) | (lb[1] & 0xFF);
        byte[] buf = new byte[len]; r = 0;
        while (r < len) { int n = in.read(buf, r, len-r); if (n < 0) throw new EOFException(); r += n; }
        return buf;
    }

    // ── Protobuf helpers ──────────────────────────────────────────────────

    private static byte[] msg(byte[]... fields) {
        int t = 0; for (byte[] f : fields) t += f.length;
        byte[] o = new byte[t]; int p = 0;
        for (byte[] f : fields) { System.arraycopy(f, 0, o, p, f.length); p += f.length; }
        return o;
    }
    private static byte[] varintField(int field, long value) {
        return concat(encodeVarint(((long) field << 3)), encodeVarint(value));
    }
    private static byte[] lenField(int field, byte[] payload) {
        byte[] tag = encodeVarint(((long) field << 3) | 2L);
        byte[] len = encodeVarint(payload.length);
        byte[] o   = new byte[tag.length + len.length + payload.length]; int p = 0;
        System.arraycopy(tag,     0, o, p, tag.length);     p += tag.length;
        System.arraycopy(len,     0, o, p, len.length);     p += len.length;
        System.arraycopy(payload, 0, o, p, payload.length);
        return o;
    }
    private static byte[] strField(int field, String s) {
        try { return lenField(field, s.getBytes("UTF-8")); } catch (Exception e) { return new byte[0]; }
    }
    private static byte[] encodeVarint(long v) {
        byte[] buf = new byte[10]; int i = 0;
        while ((v & 0xFFFFFFFFFFFFFF80L) != 0L) { buf[i++] = (byte)((v & 0x7F) | 0x80); v >>>= 7; }
        buf[i++] = (byte)(v & 0x7F);
        byte[] o = new byte[i]; System.arraycopy(buf, 0, o, 0, i); return o;
    }
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
    private static long parseVarintField(byte[] data, int tf) {
        int pos = 0;
        while (pos < data.length) {
            long tag = 0; int sh = 0;
            while (pos < data.length) { byte b = data[pos++]; tag |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
            int fn = (int)(tag >> 3), wt = (int)(tag & 7);
            if (wt == 0) {
                long v = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; v |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                if (fn == tf) return v;
            } else if (wt == 2) {
                long len = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; len |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                pos += (int) len;
            } else break;
        }
        return -1;
    }
    private static byte[] parseEmbedded(byte[] data, int tf) {
        int pos = 0;
        while (pos < data.length) {
            long tag = 0; int sh = 0;
            while (pos < data.length) { byte b = data[pos++]; tag |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
            int fn = (int)(tag >> 3), wt = (int)(tag & 7);
            if (wt == 0) { while (pos < data.length) { byte b = data[pos++]; if ((b & 0x80) == 0) break; } }
            else if (wt == 2) {
                long len = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; len |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                if (fn == tf) { byte[] r = new byte[(int)len]; System.arraycopy(data, pos, r, 0, (int)len); return r; }
                pos += (int) len;
            } else break;
        }
        return null;
    }
    public boolean isConnected() { return socket != null && !socket.isClosed() && socket.isConnected(); }
    @Override public void close() { try { if (socket != null) socket.close(); } catch (IOException ignored) {} }
}
