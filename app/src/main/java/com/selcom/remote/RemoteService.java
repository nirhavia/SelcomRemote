package com.selcom.remote;
import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

public class RemoteService extends Service {
    private static final String TAG = "RemoteService";
    private static final String CHANNEL_ID = "selcom_ch";
    private static final int NOTIF_ID = 1;
    private static final int RECONNECT_MS = 3000;

    public static final String ACTION_SEND_KEY   = "com.selcom.remote.SEND_KEY";
    public static final String ACTION_CONNECT    = "com.selcom.remote.CONNECT";
    public static final String ACTION_DISCONNECT = "com.selcom.remote.DISCONNECT";
    public static final String EXTRA_KEY_CODE    = "key_code";
    public static final String EXTRA_HOST        = "host";
    public static final String PREF_FILE         = "selcom_remote";
    public static final String PREF_HOST         = "paired_host";
    public static final String PREF_PAIRED       = "is_paired";

    private volatile RemoteProtocol protocol;
    private Thread connThread;
    private volatile boolean running = false;
    private volatile boolean intentionalStop = false;
    private volatile String currentHost;

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
        createChannel();
        ContextCompat.registerReceiver(this, keyReceiver,
            new IntentFilter(ACTION_SEND_KEY), ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        postForeground("not connected");
        if (intent != null) {
            String action = intent.getAction();
            if (ACTION_CONNECT.equals(action)) {
                String h = intent.getStringExtra(EXTRA_HOST);
                if (h != null) setHostAndConnect(h);
            } else if (ACTION_DISCONNECT.equals(action)) {
                intentionalStop = true;
                disconnect();
            } else if (ACTION_SEND_KEY.equals(action)) {
                int c = intent.getIntExtra(EXTRA_KEY_CODE, -1);
                if (c != -1) sendKey(c);
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
        getSharedPreferences(PREF_FILE, MODE_PRIVATE)
            .edit().putString(PREF_HOST, host).apply();
        startConnectionLoop();
    }

    public String getCurrentHost() { return currentHost; }

    private void startConnectionLoop() {
        if (connThread != null) connThread.interrupt();
        running = true;
        intentionalStop = false;
        connThread = new Thread(() -> {
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    updateNotif("connecting...");
                    protocol = new RemoteProtocol();
                    protocol.connectForRemote(currentHost);
                    updateNotif("connected " + currentHost);
                    while (running && !Thread.currentThread().isInterrupted()) {
                        byte[] m = protocol.readRemoteMessage();
                        int fn = protocol.parseOuterFieldNumber(m);
                        Log.d(TAG, "<- fn=" + fn + " len=" + m.length);
                        if (fn == 1) {
                            protocol.sendConfigureResponse();
                        } else if (fn == 2) {
                            protocol.sendSetActiveResponse();
                        } else if (fn == 8) {
                            protocol.sendPingResponse(protocol.parsePingValue(m));
                        } else if (fn == 40) {
                            Log.d(TAG, "remote_start received");
                        }
                    }
                } catch (Exception e) {
                    if (!running || intentionalStop) break;
                    Log.w(TAG, "conn: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    closeProtocol();
                    updateNotif("reconnecting...");
                    try { Thread.sleep(RECONNECT_MS); }
                    catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
                }
            }
            closeProtocol();
            updateNotif("not connected");
        }, "ConnThread");
        connThread.setDaemon(true);
        connThread.start();
    }

    // sendKey must NOT run on the main thread — network I/O is forbidden there.
    // We dispatch to a short-lived background thread.
    public void sendKey(int kc) {
        new Thread(() -> {
            RemoteProtocol p = protocol;
            if (p == null || !p.isConnected()) {
                Log.w(TAG, "sendKey: not connected, kc=" + kc);
                return;
            }
            try {
                p.sendKeyCode(kc);
                Log.d(TAG, "sendKey: sent kc=" + kc);
            } catch (Exception e) {
                Log.e(TAG, "sendKey kc=" + kc, e);
            }
        }).start();
    }

    public boolean isConnected() { return protocol != null && protocol.isConnected(); }
    public RemoteProtocol getClient() { return protocol; }

    private void disconnect() {
        running = false;
        if (connThread != null) { connThread.interrupt(); connThread = null; }
        closeProtocol();
    }

    private void closeProtocol() {
        RemoteProtocol p = protocol; protocol = null;
        if (p != null) try { p.close(); } catch (Exception ignored) {}
    }

    private void updateNotif(String t) { postForeground(t); }

    private void postForeground(String text) {
        Notification n = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Selcom Remote").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_send).setOngoing(true).build();
        if (Build.VERSION.SDK_INT >= 29)
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        else
            startForeground(NOTIF_ID, n);
    }

    private void createChannel() {
        NotificationChannel ch = new NotificationChannel(
            CHANNEL_ID, "Selcom Remote", NotificationManager.IMPORTANCE_LOW);
        ((NotificationManager) getSystemService(NOTIFICATION_SERVICE))
            .createNotificationChannel(ch);
    }
}
