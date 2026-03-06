package com.selcom.remote;
import android.content.*;
import android.os.*;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
public class MainActivity extends AppCompatActivity {
    private RemoteService remoteService;
    private boolean bound=false;
    private final ServiceConnection conn=new ServiceConnection(){
        @Override public void onServiceConnected(ComponentName n,IBinder b){
            remoteService=((RemoteService.LocalBinder)b).getService();
            bound=true;scheduleStatus();
        }
        @Override public void onServiceDisconnected(ComponentName n){bound=false;remoteService=null;}
    };
    @Override protected void onCreate(Bundle b){
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        Intent si=new Intent(this,RemoteService.class);
        startService(si);bindService(si,conn,BIND_AUTO_CREATE);
        setupButtons();
        findViewById(R.id.btn_find_device).setOnClickListener(v->startActivity(new Intent(this,DeviceDiscoveryActivity.class)));
    }
    private void setupButtons(){
        int[][] btns={
            {R.id.btn_1,KeyCodes.KEYCODE_1},{R.id.btn_2,KeyCodes.KEYCODE_2},{R.id.btn_3,KeyCodes.KEYCODE_3},
            {R.id.btn_4,KeyCodes.KEYCODE_4},{R.id.btn_5,KeyCodes.KEYCODE_5},{R.id.btn_6,KeyCodes.KEYCODE_6},
            {R.id.btn_7,KeyCodes.KEYCODE_7},{R.id.btn_8,KeyCodes.KEYCODE_8},{R.id.btn_9,KeyCodes.KEYCODE_9},
            {R.id.btn_0,KeyCodes.KEYCODE_0},
            {R.id.btn_up,KeyCodes.KEYCODE_DPAD_UP},{R.id.btn_down,KeyCodes.KEYCODE_DPAD_DOWN},
            {R.id.btn_left,KeyCodes.KEYCODE_DPAD_LEFT},{R.id.btn_right,KeyCodes.KEYCODE_DPAD_RIGHT},
            {R.id.btn_ok,KeyCodes.KEYCODE_DPAD_CENTER},
            {R.id.btn_back,KeyCodes.KEYCODE_BACK},{R.id.btn_home,KeyCodes.KEYCODE_HOME},{R.id.btn_menu,KeyCodes.KEYCODE_MENU},
            {R.id.btn_vol_up,KeyCodes.KEYCODE_VOLUME_UP},{R.id.btn_vol_down,KeyCodes.KEYCODE_VOLUME_DOWN},
            {R.id.btn_mute,KeyCodes.KEYCODE_VOLUME_MUTE},
            {R.id.btn_ch_up,KeyCodes.KEYCODE_CHANNEL_UP},{R.id.btn_ch_down,KeyCodes.KEYCODE_CHANNEL_DOWN},
            {R.id.btn_last_ch,KeyCodes.KEYCODE_LAST_CHANNEL},
            {R.id.btn_info,KeyCodes.KEYCODE_INFO},{R.id.btn_guide,KeyCodes.KEYCODE_GUIDE},
            {R.id.btn_play_pause,KeyCodes.KEYCODE_MEDIA_PLAY_PAUSE},{R.id.btn_stop,KeyCodes.KEYCODE_MEDIA_STOP},
            {R.id.btn_rewind,KeyCodes.KEYCODE_MEDIA_REWIND},{R.id.btn_ff,KeyCodes.KEYCODE_MEDIA_FAST_FORWARD},
        };
        for(int[] p:btns){
            View v=findViewById(p[0]);
            if(v!=null){int kc=p[1];v.setOnClickListener(view->{vibrate();sendKey(kc);}); }
        }
    }
    private void sendKey(int kc){
        if(bound&&remoteService!=null)remoteService.sendKey(kc);
        else startService(new Intent(this,RemoteService.class).setAction(RemoteService.ACTION_SEND_KEY).putExtra(RemoteService.EXTRA_KEY_CODE,kc));
    }
    private void vibrate(){
        Vibrator vib=(Vibrator)getSystemService(VIBRATOR_SERVICE);if(vib==null)return;
        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.O)
            vib.vibrate(VibrationEffect.createOneShot(30,VibrationEffect.DEFAULT_AMPLITUDE));
        else vib.vibrate(30);
    }
    private void scheduleStatus(){
        new Handler(Looper.getMainLooper()).postDelayed(()->{
            TextView tv=findViewById(R.id.tv_status);
            if(tv!=null)tv.setText(bound&&remoteService!=null&&remoteService.isConnected()?"מחובר: "+remoteService.getCurrentHost():"מנותק");
            if(!isDestroyed())scheduleStatus();
        },2000);
    }
    @Override protected void onDestroy(){super.onDestroy();if(bound){unbindService(conn);bound=false;}}
}
