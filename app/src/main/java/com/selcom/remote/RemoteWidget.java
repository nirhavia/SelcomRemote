package com.selcom.remote;
import android.app.PendingIntent;
import android.appwidget.*;
import android.content.*;
import android.os.*;
import android.widget.RemoteViews;
public class RemoteWidget extends AppWidgetProvider {
    public static final String ACTION_WIDGET_KEY="com.selcom.remote.WIDGET_KEY";
    public static final String EXTRA_KEY_CODE="key_code";
    @Override public void onUpdate(Context ctx,AppWidgetManager mgr,int[] ids){
        for(int id:ids)updateWidget(ctx,mgr,id);
    }
    public static void updateWidget(Context ctx,AppWidgetManager mgr,int id){
        RemoteViews views=new RemoteViews(ctx.getPackageName(),R.layout.widget_remote);
        int[] btnIds={R.id.w_btn_1,R.id.w_btn_2,R.id.w_btn_3,R.id.w_btn_4,R.id.w_btn_5,
            R.id.w_btn_6,R.id.w_btn_7,R.id.w_btn_8,R.id.w_btn_9,R.id.w_btn_0,
            R.id.w_btn_last_ch,R.id.w_btn_back};
        int[] kcs={KeyCodes.KEYCODE_1,KeyCodes.KEYCODE_2,KeyCodes.KEYCODE_3,KeyCodes.KEYCODE_4,
            KeyCodes.KEYCODE_5,KeyCodes.KEYCODE_6,KeyCodes.KEYCODE_7,KeyCodes.KEYCODE_8,
            KeyCodes.KEYCODE_9,KeyCodes.KEYCODE_0,
            KeyCodes.KEYCODE_LAST_CHANNEL,KeyCodes.KEYCODE_BACK};
        for(int i=0;i<btnIds.length;i++){
            Intent intent=new Intent(ctx,RemoteWidget.class).setAction(ACTION_WIDGET_KEY)
                .putExtra(EXTRA_KEY_CODE,kcs[i]).putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID,id);
            PendingIntent pi=PendingIntent.getBroadcast(ctx,btnIds[i],intent,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
            views.setOnClickPendingIntent(btnIds[i],pi);
        }
        mgr.updateAppWidget(id,views);
    }
    @Override public void onReceive(Context ctx,Intent intent){
        super.onReceive(ctx,intent);
        if(ACTION_WIDGET_KEY.equals(intent.getAction())){
            int kc=intent.getIntExtra(EXTRA_KEY_CODE,-1);if(kc==-1)return;
            Vibrator vib=(Vibrator)ctx.getSystemService(Context.VIBRATOR_SERVICE);
            if(vib!=null){
                if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.O)
                    vib.vibrate(VibrationEffect.createOneShot(30,VibrationEffect.DEFAULT_AMPLITUDE));
                else vib.vibrate(30);
            }
            ctx.startService(new Intent(ctx,RemoteService.class).setAction(RemoteService.ACTION_SEND_KEY).putExtra(RemoteService.EXTRA_KEY_CODE,kc));
        }
    }
}
