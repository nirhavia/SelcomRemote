package com.selcom.remote;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import javax.net.ssl.SSLContext;
import java.io.IOException;

public class RemoteService extends Service {
    private static final String TAG          = "RemoteService";
    private static final String CHANNEL_ID   = "selcom_channel";
    private static final int    NOTIF_ID     = 1;
    private static final int    RECONNECT_MS = 3000;

    public static final String ACTION_SEND_KEY   = "com.selcom.remote.SEND_KEY";
    public static final String ACTION_CONNECT    = "com.selcom.remote.CONNECT";
    public static final String ACTION_DISCONNECT = "com.selcom.remote.DISCONNECT";
    public static final String EXTRA_KEY_CODE    = "key_code";
    public static final String EXTRA_HOST        = "host";
    public static final String PREF_FILE         = "selcom_remote";
    public static final String PREF_HOST         = "paired_host";
    public static final String PREF_PAIRED       = "is_paired";

    private RemoteProtocol   protocol;
    private Thread           connThread;
    private Handler          mainHandler;
    private volatile boolean running         = false;
    private volatile boolean intentionalStop = false;
    private volatile String  currentHost;

    private final BroadcastReceiver keyReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context ctx, Intent intent) {
            if (ACTION_SEND_KEY.equals(intent.getAction())) {
                int code = intent.getIntExtra(EXTRA_KEY_CODE, -1);
                if (code != -1) sendKey(code);
            }
        }
    };

    private final IBinder binder = new LocalBinder();
    public class LocalBinder extends Binder {
        public RemoteService getService() { return RemoteService.this; }
    }
    @Override public IBinder onBind(Intent i) { return binder; }

    @Override public void onCreate() {
        super.onCreate();
        mainHandler = new Handler(Looper.getMainLooper());
        createChannel();
        IntentFilter f = new IntentFilter(ACTION_SEND_KEY);
        ContextCompat.registerReceiver(this, keyReceiver, f, ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        postForeground("מנותק");
        if (intent != null) {
            String action = intent.getAction();
            if (ACTION_CONNECT.equals(action)) {
                String host = intent.getStringExtra(EXTRA_HOST);
                if (host != null) setHostAndConnect(host);
            } else if (ACTION_DISCONNECT.equals(action)) {
                intentionalStop = true; disconnect();
            } else if (ACTION_SEND_KEY.equals(action)) {
                int code = intent.getIntExtra(EXTRA_KEY_CODE, -1);
                if (code != -1) sendKey(code);
            }
        }
        if (currentHost == null && !intentionalStop) {
            SharedPreferences p = getSharedPreferences(PREF_FILE, MODE_PRIVATE);
            if (p.getBoolean(PREF_PAIRED, false)) {
                String h = p.getString(PREF_HOST, null);
                if (h != null) setHostAndConnect(h);
            }
        }
        return START_STICKY;
    }

    @Override public void onDestroy() {
        super.onDestroy();
        running = false;
        try { unregisterReceiver(keyReceiver); } catch (Exception ignored) {}
        disconnect();
    }

    public void setHostAndConnect(String host) {
        currentHost = host;
        getSharedPreferences(PREF_FILE, MODE_PRIVATE).edit()
            .putString(PREF_HOST, host).apply();
        startConnectionLoop();
    }

    private void startConnectionLoop() {
        if (connThread != null) connThread.interrupt();
        running = true; intentionalStop = false;
        connThread = new Thread(() -> {
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    Log.d(TAG, "Connecting to " + currentHost);
                    updateNotif("מתחבר ל-" + currentHost);
                    CertUtils.ensureKeyExists();
                    SSLContext ssl = CertUtils.createSSLContext();
                    protocol = new RemoteProtocol(ssl);
                    protocol.connectForRemote(currentHost);
                    protocol.sendSetActive(true);
                    updateNotif("מחובר  " + currentHost);
                    while (running && !Thread.currentThread().isInterrupted()) {
                        byte[] msgData = protocol.readRemoteMessage();
                        int field = protocol.parseOuterFieldNumber(msgData);
                        if (field == 1) {
                            protocol.sendPingResponse(protocol.parsePingValue(msgData));
                        }
                    }
                } catch (Exception e) {
                    if (!running || intentionalStop) break;
                    Log.w(TAG, "Connection error: " + e.getMessage());
                    closeProtocol();
                    updateNotif("מנותק - מנסה שוב...");
                    try { Thread.sleep(RECONNECT_MS); }
                    catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
                }
            }
            closeProtocol();
            updateNotif("מנותק");
        }, "RemoteConnThread");
        connThread.setDaemon(true);
        connThread.start();
    }

    public void sendKey(int keyCode) {
        RemoteProtocol p = protocol;
        if (p != null && p.isConnected()) {
            new Thread(() -> {
                try { p.sendKeyCode(keyCode); }
                catch (IOException e) { Log.e(TAG, "sendKey: " + e.getMessage()); }
            }).start();
        }
    }

    public void disconnect() {
        running = false;
        if (connThread != null) connThread.interrupt();
        closeProtocol();
    }

    private void closeProtocol() {
        if (protocol != null) { protocol.close(); protocol = null; }
    }

    public boolean isConnected()    { return protocol != null && protocol.isConnected(); }
    public String  getCurrentHost() { return currentHost; }

    private void postForeground(String status) {
        Notification n = buildNotif(status);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        else
            startForeground(NOTIF_ID, n);
    }

    private void updateNotif(String status) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, buildNotif(status));
    }

    private Notification buildNotif(String status) {
        Intent i = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Selcom Remote")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setContentIntent(pi)
            .setOngoing(true).build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "Selcom Remote", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("שירות שלט רחוק");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }
}
