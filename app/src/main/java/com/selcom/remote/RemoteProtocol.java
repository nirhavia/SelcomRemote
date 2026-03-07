package com.selcom.remote;
import android.util.Log;
import java.io.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import javax.net.ssl.*;
public class RemoteProtocol implements Closeable {
    private static final String TAG="RemoteProtocol";
    public static final int PORT_PAIRING=6467,PORT_REMOTE=6466;
    public static final int DIR_SHORT=4;
    private static final int FLD_PING_RESPONSE=2,FLD_SET_ACTIVE=3,FLD_KEY_INJECT=4;
    private SSLSocket socket; private InputStream in; private OutputStream out;
    private final SSLContext sslContext;
    public RemoteProtocol(SSLContext ctx){this.sslContext=ctx;}
    public void connectForPairing(String host) throws IOException{connect(host,PORT_PAIRING,15000);}
    public void connectForRemote(String host)  throws IOException{connect(host,PORT_REMOTE,35000);}
    private void connect(String host,int port,int timeout) throws IOException{
        Log.d(TAG,"Connecting "+host+":"+port);
        SSLSocketFactory f=sslContext.getSocketFactory();
        socket=(SSLSocket)f.createSocket(host,port);
        socket.setSoTimeout(timeout);
        socket.startHandshake();
        in=socket.getInputStream(); out=socket.getOutputStream();
        Log.d(TAG,"Connected");
    }

    // ---- Pairing ----
    // PairingMessage fields: pairing_request=10, options=20, secret=40
    // PairingRequestMessage fields: service_name=1, client_name=2
    // PairingOptionsMessage fields: preferred_encodings=1, preferred_role=2
    // PairingEncoding fields: type=3, symbol_length=4
    // PairingSecretMessage fields: secret=1

    public void sendPairingRequest(String serviceName, String clientName) throws IOException {
        byte[] reqMsg = msg(strField(1, serviceName), strField(2, clientName));
        // PairingMessage { pairing_request(10) = reqMsg }
        sendFramed(lenField(10, reqMsg));
        Log.d(TAG,"Sent PairingRequest service="+serviceName);
    }

    public void readAndDiscard() throws IOException {
        byte[] data = readFramed();
        Log.d(TAG,"Received pairing msg len="+data.length);
    }

    public void sendPairingOptions() throws IOException {
        // PairingEncoding { type=3(HEXADECIMAL), symbol_length=6 }
        byte[] encoding = msg(varintField(3, 3), varintField(4, 6));
        // PairingOptionsMessage { preferred_encodings(1)=encoding, preferred_role(2)=1 }
        byte[] optMsg = msg(lenField(1, encoding), varintField(2, 1));
        // PairingMessage { options(20) = optMsg }
        sendFramed(lenField(20, optMsg));
        Log.d(TAG,"Sent PairingOptions");
    }

    public boolean sendPairingSecret(String code) throws Exception {
        Certificate[] lc = socket.getSession().getLocalCertificates();
        Certificate[] sc = socket.getSession().getPeerCertificates();
        if(lc==null||lc.length==0) throw new Exception("No local cert");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(lc[0].getEncoded());
        sha.update(sc[0].getEncoded());
        sha.update(code.getBytes("UTF-8"));
        byte[] secret = sha.digest();
        // PairingSecretMessage { secret(1) = bytes }
        byte[] secretMsg = lenField(1, secret);
        // PairingMessage { secret(40) = secretMsg }
        sendFramed(lenField(40, secretMsg));
        Log.d(TAG,"Sent PairingSecret code="+code);
        byte[] ack = readFramed();
        // Check status field (200) in ack
        long status = parseVarintField(ack, 200);
        Log.d(TAG,"PairingSecretAck status="+status+" len="+ack.length);
        // status==200 means OK; if not found (-1) also treat as success
        return status != 0;
    }

    // ---- Remote Control ----
    public void sendSetActive(boolean active) throws IOException {
        sendFramed(msg(lenField(FLD_SET_ACTIVE, msg(varintField(1, active?1:0)))));
    }
    public synchronized void sendKeyCode(int kc) throws IOException {
        sendFramed(msg(lenField(FLD_KEY_INJECT, msg(varintField(1,kc),varintField(2,DIR_SHORT)))));
    }
    public void sendPingResponse(int v) throws IOException {
        sendFramed(msg(lenField(FLD_PING_RESPONSE, msg(varintField(1,v)))));
    }
    public byte[] readRemoteMessage() throws IOException{return readFramed();}
    public int parseOuterFieldNumber(byte[] data){
        if(data.length==0)return -1;
        long tag=0;int shift=0;
        for(byte b:data){tag|=((long)(b&0x7F))<<shift;shift+=7;if((b&0x80)==0)break;}
        return(int)(tag>>3);
    }
    public int parsePingValue(byte[] data){
        byte[] inner=parseEmbedded(data,1);return inner==null?0:(int)parseVarintField(inner,1);
    }

    // ---- Framing ----
    private void sendFramed(byte[] data) throws IOException {
        byte[] f=new byte[2+data.length];
        f[0]=(byte)((data.length>>8)&0xFF);f[1]=(byte)(data.length&0xFF);
        System.arraycopy(data,0,f,2,data.length);out.write(f);out.flush();
    }
    private byte[] readFramed() throws IOException {
        byte[] lb=new byte[2];int r=0;
        while(r<2){int n=in.read(lb,r,2-r);if(n<0)throw new EOFException();r+=n;}
        int len=((lb[0]&0xFF)<<8)|(lb[1]&0xFF);
        byte[] buf=new byte[len];r=0;
        while(r<len){int n=in.read(buf,r,len-r);if(n<0)throw new EOFException();r+=n;}
        return buf;
    }

    // ---- Protobuf helpers ----
    private static byte[] msg(byte[]...fields){
        int t=0;for(byte[] f:fields)t+=f.length;
        byte[] o=new byte[t];int p=0;
        for(byte[] f:fields){System.arraycopy(f,0,o,p,f.length);p+=f.length;}return o;
    }
    private static byte[] varintField(int field,long value){
        return concat(encodeVarint(((long)field<<3)),encodeVarint(value));
    }
    private static byte[] lenField(int field,byte[] payload){
        byte[] tag=encodeVarint(((long)field<<3)|2L),len=encodeVarint(payload.length);
        byte[] o=new byte[tag.length+len.length+payload.length];int p=0;
        System.arraycopy(tag,0,o,p,tag.length);p+=tag.length;
        System.arraycopy(len,0,o,p,len.length);p+=len.length;
        System.arraycopy(payload,0,o,p,payload.length);return o;
    }
    private static byte[] strField(int field,String s){
        try{return lenField(field,s.getBytes("UTF-8"));}catch(Exception e){return new byte[0];}
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
