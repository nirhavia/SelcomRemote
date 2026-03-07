package com.selcom.remote;
import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

public class RemoteService extends Service {
    private static final String TAG="RemoteService", CHANNEL_ID="selcom_ch";
    private static final int NOTIF_ID=1, RECONNECT_MS=3000;
    public static final String ACTION_SEND_KEY="com.selcom.remote.SEND_KEY";
    public static final String ACTION_CONNECT="com.selcom.remote.CONNECT";
    public static final String ACTION_DISCONNECT="com.selcom.remote.DISCONNECT";
    public static final String EXTRA_KEY_CODE="key_code", EXTRA_HOST="host";
    public static final String PREF_FILE="selcom_remote", PREF_HOST="paired_host", PREF_PAIRED="is_paired";

    private RemoteProtocol protocol;
    private Thread connThread;
    private volatile boolean running=false, intentionalStop=false;
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
    public class LocalBinder extends Binder { public RemoteService getService() { return RemoteService.this; } }
    @Override public IBinder onBind(Intent i) { return binder; }

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
        ContextCompat.registerReceiver(this, keyReceiver,
            new IntentFilter(ACTION_SEND_KEY), ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        postForeground("לא מחובר");
        if (intent != null) {
            String action = intent.getAction();
            if (ACTION_CONNECT.equals(action)) {
                String h = intent.getStringExtra(EXTRA_HOST);
                if (h != null) setHostAndConnect(h);
            } else if (ACTION_DISCONNECT.equals(action)) {
                intentionalStop = true; disconnect();
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
        super.onDestroy(); running = false;
        try { unregisterReceiver(keyReceiver); } catch (Exception ignored) {}
        disconnect();
    }

    public void setHostAndConnect(String host) {
        currentHost = host;
        getSharedPreferences(PREF_FILE, MODE_PRIVATE).edit().putString(PREF_HOST, host).apply();
        startConnectionLoop();
    }

    private void startConnectionLoop() {
        if (connThread != null) connThread.interrupt();
        running = true; intentionalStop = false;
        connThread = new Thread(() -> {
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    updateNotif("מתחבר...");
                    protocol = new RemoteProtocol();
                    protocol.connectForRemote(currentHost);
                    updateNotif("מחובר " + currentHost);
                    // Read loop - handle pings (field 9 = [74,...])
                    while (running && !Thread.currentThread().isInterrupted()) {
                        byte[] m = protocol.readRemoteMessage();
                        int fn = protocol.parseOuterFieldNumber(m);
                        Log.d(TAG, "recv field=" + fn + " len=" + m.length);
                        if (fn == 9) {  // ping: first byte 74 = field9,wire2
                            protocol.sendPingResponse(protocol.parsePingValue(m));
                        }
                        // fn==4: key_inject ack (ignore)
                        // fn==3: set_active ack (ignore)
                    }
                } catch (Exception e) {
                    if (!running || intentionalStop) break;
                    Log.w(TAG, "conn error: " + e.getMessage());
                    closeProtocol();
                    updateNotif("לא מחובר - מנסה שוב...");
                    try { Thread.sleep(RECONNECT_MS); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); break;
                    }
                }
            }
            closeProtocol(); updateNotif("לא מחובר");
        }, "ConnThread");
        connThread.setDaemon(true); connThread.start();
    }

    public void sendKey(int kc) {
        RemoteProtocol p = protocol;
        if (p != null && p.isConnected()) new Thread(() -> {
            try { p.sendKeyCode(kc); }
            catch (Exception e) { Log.e(TAG, "sendKey: " + e.getMessage()); }
        }).start();
        else Log.w(TAG, "sendKey: not connected");
    }

    public boolean isConnected() {
        return protocol != null && protocol.isConnected();
    }

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

    private void updateNotif(String text) {
        postForeground(text);
    }

    private void postForeground(String text) {
        Notification n = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Selcom Remote")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_send)
            .setOngoing(true).build();
        if (Build.VERSION.SDK_INT >= 29)
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        else
            startForeground(NOTIF_ID, n);
    }

    private void createChannel() {
        NotificationChannel ch = new NotificationChannel(
            CHANNEL_ID, "Selcom Remote", NotificationManager.IMPORTANCE_LOW);
        ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
    }
}
