package com.selcom.remote;
import android.content.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import javax.net.ssl.SSLContext;
import java.util.concurrent.*;
public class PairingActivity extends AppCompatActivity {
    public static final String EXTRA_HOST="host";
    private String host;
    private final StringBuilder code=new StringBuilder();
    private TextView tvCode;
    private Button btnPair;
    private ProgressBar progress;
    private View keyboardArea;
    private final ExecutorService ex=Executors.newSingleThreadExecutor();
    private final Handler mh=new Handler(Looper.getMainLooper());
    @Override protected void onCreate(Bundle b){
        super.onCreate(b);
        setContentView(R.layout.activity_pairing);
        host=getIntent().getStringExtra(EXTRA_HOST);
        if(host==null){finish();return;}
        tvCode=findViewById(R.id.tv_pairing_code);
        btnPair=findViewById(R.id.btn_submit_pair);
        progress=findViewById(R.id.pairing_progress);
        keyboardArea=findViewById(R.id.keyboard_scroll);
        buildKeyboard();updateDisplay();
        btnPair.setOnClickListener(v->{if(code.length()==6)doPairing();});
        findViewById(R.id.btn_delete).setOnClickListener(v->{
            if(code.length()>0){code.deleteCharAt(code.length()-1);updateDisplay();}
        });
    }
    private void buildKeyboard(){
        LinearLayout container=findViewById(R.id.keyboard_container);
        float dp=getResources().getDisplayMetrics().density;
        int h=(int)(54*dp);
        String[] rows={"1234567890","ABCDEF","abcdef"};
        for(String row:rows){
            LinearLayout rl=new LinearLayout(this);
            rl.setOrientation(LinearLayout.HORIZONTAL);
            rl.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT));
            rl.setGravity(Gravity.CENTER);
            for(char c:row.toCharArray()){
                Button btn=new Button(this);btn.setText(String.valueOf(c));btn.setTextSize(18f);
                LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,h);lp.weight=1;lp.setMargins(3,3,3,3);
                btn.setLayoutParams(lp);
                char cu=Character.toUpperCase(c);
                btn.setOnClickListener(v->{if(code.length()<6){code.append(cu);updateDisplay();}});
                rl.addView(btn);
            }
            container.addView(rl);
        }
    }
    private void updateDisplay(){
        StringBuilder d=new StringBuilder(code);
        for(int i=code.length();i<6;i++)d.append('_');
        tvCode.setText(d.toString());btnPair.setEnabled(code.length()==6);
    }
    private void doPairing(){
        String pc=code.toString().toUpperCase();
        progress.setVisibility(View.VISIBLE);keyboardArea.setVisibility(View.GONE);btnPair.setEnabled(false);
        ex.submit(()->{
            try{
                CertUtils.ensureKeyExists();
                SSLContext ssl=CertUtils.createSSLContext();
                RemoteProtocol rp=new RemoteProtocol(ssl);
                rp.connectForPairing(host);
                // Step 1: send pairing request
                rp.sendPairingRequest("androidtvremote2","SelcomRemote");
                // Step 2: read request ack
                rp.readAndDiscard();
                // Step 3: send options → TV shows code on screen
                rp.sendPairingOptions();
                // Step 4: read options ack
                rp.readAndDiscard();
                // Step 5: send secret with user code
                boolean ok=rp.sendPairingSecret(pc);
                rp.close();
                mh.post(()->{
                    progress.setVisibility(View.GONE);
                    if(ok){
                        getSharedPreferences(RemoteService.PREF_FILE,MODE_PRIVATE).edit()
                            .putBoolean(RemoteService.PREF_PAIRED,true).putString(RemoteService.PREF_HOST,host).apply();
                        Toast.makeText(this,"הצימוד הצליח!",Toast.LENGTH_SHORT).show();
                        startService(new Intent(this,RemoteService.class)
                            .setAction(RemoteService.ACTION_CONNECT)
                            .putExtra(RemoteService.EXTRA_HOST,host));
                        startActivity(new Intent(this,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
                        finish();
                    }else{
                        keyboardArea.setVisibility(View.VISIBLE);
                        Toast.makeText(this,"קוד שגוי - נסה שוב",Toast.LENGTH_SHORT).show();
                    }
                });
            }catch(Exception e){
                mh.post(()->{
                    progress.setVisibility(View.GONE);keyboardArea.setVisibility(View.VISIBLE);
                    Toast.makeText(this,"שגיאה: "+e.getMessage(),Toast.LENGTH_LONG).show();
                });
            }
        });
    }
    @Override protected void onDestroy(){super.onDestroy();ex.shutdownNow();}
}
