package com.selcom.remote;

import android.util.Log;
import java.io.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import javax.net.ssl.*;

/**
 * Android TV Remote Control Protocol v2.
 * Pairing -> port 6467 (TLS)
 * Remote  -> port 6466 (TLS)
 * Framing -> 2-byte big-endian length prefix + protobuf message bytes.
 */
public class RemoteProtocol implements Closeable {
    private static final String TAG = "RemoteProtocol";
    public static final int PORT_PAIRING = 6467;
    public static final int PORT_REMOTE  = 6466;

    private static final int MSG_PAIRING_REQUEST = 10;
    private static final int MSG_PAIRING_OPTIONS = 20;
    private static final int MSG_PAIRING_SECRET  = 40;

    public static final int DIR_SHORT = 4;

    private static final int FLD_PING_RESPONSE = 2;
    private static final int FLD_SET_ACTIVE    = 3;
    private static final int FLD_KEY_INJECT    = 4;

    private SSLSocket    socket;
    private InputStream  in;
    private OutputStream out;
    private final SSLContext sslContext;

    public RemoteProtocol(SSLContext ctx) { this.sslContext = ctx; }

    // ---- Connection ---------------------------------------------------

    public void connectForPairing(String host) throws IOException { connect(host, PORT_PAIRING, 12000); }
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

    // ---- Pairing ------------------------------------------------------

    public void sendPairingRequest(String serviceName, String clientName) throws IOException {
        byte[] req = msg(strField(1, serviceName), strField(2, clientName));
        sendFramed(msg(varintField(1, MSG_PAIRING_REQUEST), lenField(10, req)));
    }

    public int readPairingMessageType() throws IOException {
        byte[] data = readFramed();
        return (int) parseVarintField(data, 1);
    }

    public void sendPairingOptions() throws IOException {
        byte[] enc = msg(varintField(3, 3), varintField(4, 6));
        byte[] opt = msg(lenField(1, enc), varintField(2, 1));
        sendFramed(msg(varintField(1, MSG_PAIRING_OPTIONS), lenField(21, opt)));
    }

    public boolean sendPairingSecret(String code) throws Exception {
        Certificate[] localCerts  = socket.getSession().getLocalCertificates();
        Certificate[] serverCerts = socket.getSession().getPeerCertificates();
        if (localCerts == null || localCerts.length == 0)
            throw new Exception("No local certificate");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(localCerts[0].getEncoded());
        sha.update(serverCerts[0].getEncoded());
        sha.update(code.getBytes("UTF-8"));
        byte[] secret    = sha.digest();
        byte[] secretMsg = msg(lenField(1, secret));
        sendFramed(msg(varintField(1, MSG_PAIRING_SECRET), lenField(40, secretMsg)));
        byte[] resp   = readFramed();
        long   status = parseVarintField(resp, 200);
        Log.d(TAG, "PairingSecretAck status=" + status);
        return status == 200;
    }

    // ---- Remote Control -----------------------------------------------

    public void sendSetActive(boolean active) throws IOException {
        sendFramed(msg(lenField(FLD_SET_ACTIVE, msg(varintField(1, active ? 1 : 0)))));
    }

    public synchronized void sendKeyCode(int keyCode) throws IOException {
        byte[] inner = msg(varintField(1, keyCode), varintField(2, DIR_SHORT));
        sendFramed(msg(lenField(FLD_KEY_INJECT, inner)));
    }

    public void sendPingResponse(int val) throws IOException {
        sendFramed(msg(lenField(FLD_PING_RESPONSE, msg(varintField(1, val)))));
    }

    public byte[] readRemoteMessage() throws IOException { return readFramed(); }

    public int parseOuterFieldNumber(byte[] data) {
        if (data.length == 0) return -1;
        long tag = 0; int shift = 0;
        for (byte b : data) {
            tag |= ((long)(b & 0x7F)) << shift; shift += 7;
            if ((b & 0x80) == 0) break;
        }
        return (int)(tag >> 3);
    }

    public int parsePingValue(byte[] data) {
        byte[] inner = parseEmbedded(data, 1);
        return inner == null ? 0 : (int) parseVarintField(inner, 1);
    }

    // ---- Framing ------------------------------------------------------

    private void sendFramed(byte[] data) throws IOException {
        int len = data.length;
        byte[] framed = new byte[2 + len];
        framed[0] = (byte)((len >> 8) & 0xFF);
        framed[1] = (byte)(len        & 0xFF);
        System.arraycopy(data, 0, framed, 2, len);
        out.write(framed); out.flush();
    }

    private byte[] readFramed() throws IOException {
        byte[] lb = new byte[2]; int r = 0;
        while (r < 2) { int n = in.read(lb, r, 2-r); if (n < 0) throw new EOFException(); r += n; }
        int len = ((lb[0] & 0xFF) << 8) | (lb[1] & 0xFF);
        byte[] buf = new byte[len]; r = 0;
        while (r < len) { int n = in.read(buf, r, len-r); if (n < 0) throw new EOFException(); r += n; }
        return buf;
    }

    // ---- Protobuf helpers --------------------------------------------

    private static byte[] msg(byte[]... fields) {
        int total = 0;
        for (byte[] f : fields) total += f.length;
        byte[] out = new byte[total]; int pos = 0;
        for (byte[] f : fields) { System.arraycopy(f, 0, out, pos, f.length); pos += f.length; }
        return out;
    }

    private static byte[] varintField(int field, long value) {
        return concat(encodeVarint(((long)field << 3)), encodeVarint(value));
    }

    private static byte[] lenField(int field, byte[] payload) {
        byte[] tag = encodeVarint(((long)field << 3) | 2L);
        byte[] len = encodeVarint(payload.length);
        byte[] out = new byte[tag.length + len.length + payload.length];
        int p = 0;
        System.arraycopy(tag,     0, out, p, tag.length);     p += tag.length;
        System.arraycopy(len,     0, out, p, len.length);     p += len.length;
        System.arraycopy(payload, 0, out, p, payload.length);
        return out;
    }

    private static byte[] strField(int field, String s) {
        try { return lenField(field, s.getBytes("UTF-8")); }
        catch (Exception e) { return new byte[0]; }
    }

    private static byte[] encodeVarint(long v) {
        byte[] buf = new byte[10]; int i = 0;
        while ((v & 0xFFFFFFFFFFFFFF80L) != 0L) {
            buf[i++] = (byte)((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        buf[i++] = (byte)(v & 0x7F);
        byte[] out = new byte[i];
        System.arraycopy(buf, 0, out, 0, i);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0,        a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private static long parseVarintField(byte[] data, int targetField) {
        int pos = 0;
        while (pos < data.length) {
            long tag = 0; int sh = 0;
            while (pos < data.length) { byte b = data[pos++]; tag |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
            int fn = (int)(tag >> 3); int wt = (int)(tag & 7);
            if (wt == 0) {
                long v = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; v |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                if (fn == targetField) return v;
            } else if (wt == 2) {
                long len = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; len |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                pos += (int)len;
            } else break;
        }
        return -1;
    }

    private static byte[] parseEmbedded(byte[] data, int targetField) {
        int pos = 0;
        while (pos < data.length) {
            long tag = 0; int sh = 0;
            while (pos < data.length) { byte b = data[pos++]; tag |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
            int fn = (int)(tag >> 3); int wt = (int)(tag & 7);
            if (wt == 0) { while (pos < data.length) { byte b = data[pos++]; if ((b & 0x80) == 0) break; } }
            else if (wt == 2) {
                long len = 0; sh = 0;
                while (pos < data.length) { byte b = data[pos++]; len |= ((long)(b & 0x7F)) << sh; sh += 7; if ((b & 0x80) == 0) break; }
                if (fn == targetField) {
                    byte[] r = new byte[(int)len];
                    System.arraycopy(data, pos, r, 0, (int)len);
                    return r;
                }
                pos += (int)len;
            } else break;
        }
        return null;
    }

    public boolean isConnected() {
        return socket != null && !socket.isClosed() && socket.isConnected();
    }

    @Override public void close() {
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
    }
}
