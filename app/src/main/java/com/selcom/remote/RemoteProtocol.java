package com.selcom.remote;
import android.util.Log;
import java.io.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import javax.net.ssl.*;

public class RemoteProtocol implements Closeable {
    private static final String TAG       = "RemoteProtocol";
    public  static final int PORT_PAIRING = 6467;
    public  static final int PORT_REMOTE  = 6466;
    private static final int VERSION      = 2;
    private static final int STATUS_OK    = 200;
    public  static final int DIR_SHORT    = 4;

    private SSLSocket    socket;
    private InputStream  in;
    private OutputStream out;
    private final SSLContext sslContext;

    public RemoteProtocol(SSLContext ctx) { this.sslContext = ctx; }

    public void connectForPairing(String host) throws IOException { connect(host, PORT_PAIRING, 60000); }
    public void connectForRemote(String host)  throws IOException { connect(host, PORT_REMOTE,  35000); }

    private void connect(String host, int port, int timeout) throws IOException {
        Log.d(TAG, "Connecting " + host + ":" + port);
        SSLSocketFactory f = sslContext.getSocketFactory();
        socket = (SSLSocket) f.createSocket(host, port);
        socket.setSoTimeout(timeout);
        socket.startHandshake();
        in  = socket.getInputStream();
        out = socket.getOutputStream();
        Log.d(TAG, "Connected OK");
    }

    // Step 1: PairingRequest
    // field 10 = pairing_request { service_name(1), client_name(2) }
    public void sendPairingRequest(String svc, String client) throws IOException {
        byte[] inner = msg(strField(1, svc), strField(2, client));
        sendFramed(pairingMsg(lenField(10, inner)));
        Log.d(TAG, "-> PairingRequest");
    }

    // Step 2: PairingOptions
    // field 20 = options {
    //   field 1 = encoding { field 1=3(HEX), field 2=6(len) }
    //   field 3 = preferred_role = 1 (INPUT)   ← field 3, NOT field 2!
    // }
    public void sendPairingOptions() throws IOException {
        byte[] enc    = msg(varintField(1, 3), varintField(2, 6));
        byte[] optMsg = msg(lenField(1, enc),  varintField(3, 1)); // field 3!
        sendFramed(pairingMsg(lenField(20, optMsg)));
        Log.d(TAG, "-> PairingOptions");
    }

    // Step 3: PairingConfiguration → TV shows code
    // field 30 = configuration {
    //   field 1 = encoding { field 1=3(HEX), field 2=6(len) }
    //   field 2 = preferred_role = 1 (INPUT)   ← field 2 here
    // }
    public void sendPairingConfig() throws IOException {
        byte[] enc    = msg(varintField(1, 3), varintField(2, 6));
        byte[] cfgMsg = msg(lenField(1, enc),  varintField(2, 1)); // field 2
        sendFramed(pairingMsg(lenField(30, cfgMsg)));
        Log.d(TAG, "-> PairingConfig  (TV should show code)");
    }

    public void readAndDiscard() throws IOException {
        byte[] d = readFramed();
        Log.d(TAG, "<- ack len=" + d.length);
    }

    // Step 5: send secret
    // secret = SHA256(clientMod + clientExp + serverMod + serverExp + hexToBytes(code))
    public boolean sendPairingSecret(String hexCode) throws Exception {
        Certificate[] lc = socket.getSession().getLocalCertificates();
        Certificate[] sc = socket.getSession().getPeerCertificates();
        if (lc == null || lc.length == 0) throw new Exception("No local cert");
        RSAPublicKey ck = (RSAPublicKey) lc[0].getPublicKey();
        RSAPublicKey sk = (RSAPublicKey) sc[0].getPublicKey();
        byte[] codeBytes = hexStringToBytes(hexCode);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(trim(ck.getModulus().toByteArray()));
        sha.update(trim(ck.getPublicExponent().toByteArray()));
        sha.update(trim(sk.getModulus().toByteArray()));
        sha.update(trim(sk.getPublicExponent().toByteArray()));
        sha.update(codeBytes);
        byte[] secret = sha.digest();
        sendFramed(pairingMsg(lenField(40, lenField(1, secret))));
        Log.d(TAG, "-> PairingSecret code=" + hexCode);
        byte[] ack = readFramed();
        long status = parseVarintField(ack, 2);
        Log.d(TAG, "<- SecretAck status=" + status);
        return status == STATUS_OK;
    }

    private static byte[] trim(byte[] b) {
        int s = 0; while (s < b.length - 1 && b[s] == 0) s++;
        byte[] r = new byte[b.length - s]; System.arraycopy(b, s, r, 0, r.length); return r;
    }

    private static byte[] hexStringToBytes(String hex) throws Exception {
        hex = hex.toUpperCase().replaceAll("[^0-9A-F]", "");
        if (hex.length() % 2 != 0) hex = "0" + hex;
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < r.length; i++)
            r[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
        return r;
    }

    private static byte[] pairingMsg(byte[] payload) {
        return msg(varintField(1, VERSION), varintField(2, STATUS_OK), payload);
    }

    // ── Remote ────────────────────────────────────────────────────────────────
    public void sendSetActive(boolean a) throws IOException {
        sendFramed(msg(lenField(3, msg(varintField(1, a?1:0)))));
    }
    public synchronized void sendKeyCode(int kc) throws IOException {
        sendFramed(msg(lenField(4, msg(varintField(1, kc), varintField(2, DIR_SHORT)))));
    }
    public void sendPingResponse(int v) throws IOException {
        sendFramed(msg(lenField(2, msg(varintField(1, v)))));
    }
    public byte[] readRemoteMessage() throws IOException { return readFramed(); }
    public int parseOuterFieldNumber(byte[] data) {
        if (data.length == 0) return -1;
        long tag = 0; int sh = 0;
        for (byte b : data) { tag |= ((long)(b&0x7F))<<sh; sh+=7; if((b&0x80)==0) break; }
        return (int)(tag>>3);
    }
    public int parsePingValue(byte[] data) {
        byte[] inner = parseEmbedded(data, 1);
        return inner == null ? 0 : (int)parseVarintField(inner, 1);
    }

    // ── Framing ───────────────────────────────────────────────────────────────
    private void sendFramed(byte[] data) throws IOException {
        byte[] f = new byte[2+data.length];
        f[0]=(byte)((data.length>>8)&0xFF); f[1]=(byte)(data.length&0xFF);
        System.arraycopy(data,0,f,2,data.length); out.write(f); out.flush();
    }
    private byte[] readFramed() throws IOException {
        byte[] lb=new byte[2]; int r=0;
        while(r<2){int n=in.read(lb,r,2-r);if(n<0)throw new EOFException();r+=n;}
        int len=((lb[0]&0xFF)<<8)|(lb[1]&0xFF);
        byte[] buf=new byte[len]; r=0;
        while(r<len){int n=in.read(buf,r,len-r);if(n<0)throw new EOFException();r+=n;}
        return buf;
    }

    // ── Protobuf helpers ──────────────────────────────────────────────────────
    private static byte[] msg(byte[]...fields){
        int t=0;for(byte[] f:fields)t+=f.length;
        byte[] o=new byte[t];int p=0;
        for(byte[] f:fields){System.arraycopy(f,0,o,p,f.length);p+=f.length;}return o;
    }
    private static byte[] varintField(int field,long val){
        return concat(encodeVarint((long)field<<3),encodeVarint(val));
    }
    private static byte[] lenField(int field,byte[] payload){
        byte[] tag=encodeVarint(((long)field<<3)|2L),len=encodeVarint(payload.length);
        byte[] o=new byte[tag.length+len.length+payload.length];int p=0;
        System.arraycopy(tag,0,o,p,tag.length);p+=tag.length;
        System.arraycopy(len,0,o,p,len.length);p+=len.length;
        System.arraycopy(payload,0,o,p,payload.length);return o;
    }
    private static byte[] strField(int f,String s){
        try{return lenField(f,s.getBytes("UTF-8"));}catch(Exception e){return new byte[0];}
    }
    private static byte[] encodeVarint(long v){
        byte[] buf=new byte[10];int i=0;
        while((v&0xFFFFFFFFFFFFFF80L)!=0L){buf[i++]=(byte)((v&0x7F)|0x80);v>>>=7;}
        buf[i++]=(byte)(v&0x7F);byte[] o=new byte[i];System.arraycopy(buf,0,o,0,i);return o;
    }
    private static byte[] concat(byte[] a,byte[] b){
        byte[] c=new byte[a.length+b.length];
        System.arraycopy(a,0,c,0,a.length);System.arraycopy(b,0,c,a.length,b.length);return c;
    }
    private static long parseVarintField(byte[] data,int tf){
        int pos=0;
        while(pos<data.length){
            long tag=0;int sh=0;
            while(pos<data.length){byte b=data[pos++];tag|=((long)(b&0x7F))<<sh;sh+=7;if((b&0x80)==0)break;}
            int fn=(int)(tag>>3),wt=(int)(tag&7);
            if(wt==0){long v=0;sh=0;while(pos<data.length){byte b=data[pos++];v|=((long)(b&0x7F))<<sh;sh+=7;if((b&0x80)==0)break;}if(fn==tf)return v;}
            else if(wt==2){long len=0;sh=0;while(pos<data.length){byte b=data[pos++];len|=((long)(b&0x7F))<<sh;sh+=7;if((b&0x80)==0)break;}pos+=(int)len;}
            else break;
        }
        return -1;
    }
    private static byte[] parseEmbedded(byte[] data,int tf){
        int pos=0;
        while(pos<data.length){
            long tag=0;int sh=0;
            while(pos<data.length){byte b=data[pos++];tag|=((long)(b&0x7F))<<sh;sh+=7;if((b&0x80)==0)break;}
            int fn=(int)(tag>>3),wt=(int)(tag&7);
            if(wt==0){while(pos<data.length){byte b=data[pos++];if((b&0x80)==0)break;}}
            else if(wt==2){
                long len=0;sh=0;while(pos<data.length){byte b=data[pos++];len|=((long)(b&0x7F))<<sh;sh+=7;if((b&0x80)==0)break;}
                if(fn==tf){byte[] r=new byte[(int)len];System.arraycopy(data,pos,r,0,(int)len);return r;}
                pos+=(int)len;
            }else break;
        }
        return null;
    }
    public boolean isConnected(){return socket!=null&&!socket.isClosed()&&socket.isConnected();}
    @Override public void close(){try{if(socket!=null)socket.close();}catch(IOException ignored){}}
}
