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

    public static final String EXTRA_HOST = "host";

    private String host;
    private RemoteProtocol rp;
    private StringBuilder code = new StringBuilder();
    private ExecutorService ex = Executors.newSingleThreadExecutor();
    private Handler mh = new Handler(Looper.getMainLooper());

    private TextView tvCode;
    private ProgressBar progress;
    private View keyboardArea;
    private LinearLayout keyboardContainer;
    private Button btnPair;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_pairing);
        host = getIntent().getStringExtra(EXTRA_HOST);
        if (host == null) { finish(); return; }

        tvCode          = findViewById(R.id.tv_pairing_code);
        progress        = findViewById(R.id.pairing_progress);
        keyboardArea    = findViewById(R.id.keyboard_scroll);
        keyboardContainer = findViewById(R.id.keyboard_container);
        btnPair         = findViewById(R.id.btn_submit_pair);

        progress.setVisibility(View.GONE);
        btnPair.setEnabled(false);

        buildKeyboard();
        updateDisplay();

        btnPair.setOnClickListener(v -> { if (code.length() == 6) doSendSecret(); });
        findViewById(R.id.btn_delete).setOnClickListener(v -> {
            if (code.length() > 0) { code.deleteCharAt(code.length() - 1); updateDisplay(); }
        });

        startPairingHandshake();
    }

    private void buildKeyboard() {
        float dp = getResources().getDisplayMetrics().density;
        int h = (int)(54 * dp);
        String[] rows = {"1234567890", "ABCDEF"};
        for (String row : rows) {
            LinearLayout rl = new LinearLayout(this);
            rl.setOrientation(LinearLayout.HORIZONTAL);
            rl.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
            for (char c : row.toCharArray()) {
                Button btn = new Button(this);
                btn.setText(String.valueOf(c));
                btn.setTextSize(18f);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, h);
                lp.weight = 1; lp.setMargins(2,2,2,2);
                btn.setLayoutParams(lp);
                btn.setOnClickListener(v -> {
                    if (code.length() < 6) { code.append(c); updateDisplay(); }
                });
                rl.addView(btn);
            }
            keyboardContainer.addView(rl);
        }
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

    private void doSendSecret() {
        String pc = code.toString().toUpperCase();
        progress.setVisibility(View.VISIBLE);
        keyboardArea.setVisibility(View.GONE);
        btnPair.setEnabled(false);
        ex.submit(() -> {
            try {
                boolean ok = rp.sendPairingSecret(pc);
                try { rp.readAndDiscard(); } catch (Exception ignored) {} // read pairing_result
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
        for (int i = 0; i < 6; i++) d.append(i < code.length() ? code.charAt(i) : '_');
        tvCode.setText(d.toString());
        btnPair.setEnabled(code.length() == 6);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        final RemoteProtocol toClose = rp; rp = null;
        ex.submit(() -> { if (toClose != null) toClose.close(); });
        ex.shutdownNow();
    }
}
