package com.selcom.remote;

import android.content.*;

public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            SharedPreferences p = ctx.getSharedPreferences(
                RemoteService.PREF_FILE, Context.MODE_PRIVATE);
            if (p.getBoolean(RemoteService.PREF_PAIRED, false))
                ctx.startService(new Intent(ctx, RemoteService.class));
        }
    }
}
