package com.selcom.remote;
import android.content.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PairingActivity extends AppCompatActivity {

    private String host;
    private RemoteProtocol rp;
    private StringBuilder code = new StringBuilder();
    private ExecutorService ex = Executors.newSingleThreadExecutor();
    private Handler mh = new Handler(Looper.getMainLooper());

    private TextView tvCode;
    private View progress;
    private View keyboardArea;
    private Button btnPair;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        host = getIntent().getStringExtra("host");
        if (host == null) { finish(); return; }
        setContentView(R.layout.activity_pairing);
        tvCode      = findViewById(R.id.tv_code);
        progress    = findViewById(R.id.progress);
        keyboardArea= findViewById(R.id.keyboard_area);
        btnPair     = findViewById(R.id.btn_pair);
        progress.setVisibility(View.GONE);
        startPairingHandshake();
    }

    private void startPairingHandshake() {
        progress.setVisibility(View.VISIBLE);
        keyboardArea.setVisibility(View.GONE);
        ex.submit(() -> {
            try {
                rp = new RemoteProtocol();
                rp.connectForPairing(host);
                rp.sendPairingRequest(); rp.readAndDiscard();
                rp.sendPairingOptions(); rp.readAndDiscard();
                rp.sendPairingConfig();  rp.readAndDiscard();
                mh.post(() -> {
                    progress.setVisibility(View.GONE);
                    keyboardArea.setVisibility(View.VISIBLE);
                    Toast.makeText(this, "Enter PIN shown on TV", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                mh.post(() -> {
                    Toast.makeText(this, "Connection failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    finish();
                });
            }
        });
    }

    public void onKey(View v) {
        if (code.length() >= 6) return;
        String t = ((Button) v).getText().toString();
        code.append(t);
        updateDisplay();
        if (code.length() == 6) btnPair.setEnabled(true);
    }

    public void onBackspace(View v) {
        if (code.length() > 0) { code.deleteCharAt(code.length() - 1); updateDisplay(); }
        btnPair.setEnabled(false);
    }

    public void onPair(View v) {
        doSendSecret();
    }

    private void doSendSecret() {
        String pc = code.toString().toUpperCase();
        progress.setVisibility(View.VISIBLE);
        keyboardArea.setVisibility(View.GONE);
        btnPair.setEnabled(false);
        ex.submit(() -> {
            try {
                boolean ok = rp.sendPairingSecret(pc);
                rp.readAndDiscard(); // read pairing_result from TV
                mh.post(() -> {
                    progress.setVisibility(View.GONE);
                    if (ok) {
                        getSharedPreferences(RemoteService.PREF_FILE, MODE_PRIVATE).edit()
                            .putBoolean(RemoteService.PREF_PAIRED, true)
                            .putString(RemoteService.PREF_HOST, host).apply();
                        Toast.makeText(this, "Pairing OK!", Toast.LENGTH_SHORT).show();
                        ContextCompat.startForegroundService(this,
                            new Intent(this, RemoteService.class)
                                .setAction(RemoteService.ACTION_CONNECT)
                                .putExtra(RemoteService.EXTRA_HOST, host));
                        startActivity(new Intent(this, MainActivity.class)
                            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
                        finish();
                    } else {
                        code.setLength(0); updateDisplay();
                        keyboardArea.setVisibility(View.VISIBLE);
                        Toast.makeText(this, "Wrong code - try again", Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Exception e) {
                mh.post(() -> {
                    progress.setVisibility(View.GONE);
                    code.setLength(0); updateDisplay();
                    keyboardArea.setVisibility(View.VISIBLE);
                    Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void updateDisplay() {
        StringBuilder d = new StringBuilder();
        for (int i = 0; i < 6; i++) d.append(i < code.length() ? code.charAt(i) : '-');
        tvCode.setText(d.toString());
        btnPair.setEnabled(code.length() == 6);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        final RemoteProtocol toClose = rp;
        rp = null;
        ex.submit(() -> { if (toClose != null) toClose.close(); });
        ex.shutdownNow();
    }
}
