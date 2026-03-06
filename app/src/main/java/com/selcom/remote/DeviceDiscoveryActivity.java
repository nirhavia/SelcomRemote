package com.selcom.remote;
import android.content.*;
import android.net.nsd.*;
import android.os.*;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import java.net.InetAddress;
import java.util.*;
public class DeviceDiscoveryActivity extends AppCompatActivity {
    private static final String SVC_TYPE="_androidtvremote2._tcp.";
    private NsdManager nsdManager;
    private NsdManager.DiscoveryListener discListener;
    private ArrayAdapter<String> adapter;
    private final List<String> names=new ArrayList<>(),hosts=new ArrayList<>();
    private ProgressBar progress;
    private EditText etIp;
    private Handler mainHandler;
    @Override protected void onCreate(Bundle b){
        super.onCreate(b);
        setContentView(R.layout.activity_discovery);
        mainHandler=new Handler(Looper.getMainLooper());
        ListView lv=findViewById(R.id.device_list);
        progress=findViewById(R.id.discovery_progress);
        etIp=findViewById(R.id.et_manual_ip);
        adapter=new ArrayAdapter<>(this,android.R.layout.simple_list_item_1,names);
        lv.setAdapter(adapter);
        lv.setOnItemClickListener((p,v,pos,id)->openPairing(hosts.get(pos)));
        findViewById(R.id.btn_manual_connect).setOnClickListener(v->{
            String ip=etIp.getText().toString().trim();
            if(!ip.isEmpty())openPairing(ip);
        });
        nsdManager=(NsdManager)getSystemService(NSD_SERVICE);
        startDiscovery();
    }
    private void startDiscovery(){
        progress.setVisibility(View.VISIBLE);
        discListener=new NsdManager.DiscoveryListener(){
            public void onStartDiscoveryFailed(String t,int e){mainHandler.post(()->progress.setVisibility(View.GONE));}
            public void onStopDiscoveryFailed(String t,int e){}
            public void onDiscoveryStarted(String t){}
            public void onDiscoveryStopped(String t){}
            public void onServiceFound(NsdServiceInfo info){
                nsdManager.resolveService(info,new NsdManager.ResolveListener(){
                    public void onResolveFailed(NsdServiceInfo i,int e){}
                    public void onServiceResolved(NsdServiceInfo i){
                        InetAddress addr=i.getHost();if(addr==null)return;
                        String host=addr.getHostAddress();
                        String name=i.getServiceName()+" ("+host+")";
                        mainHandler.post(()->{
                            if(!hosts.contains(host)){hosts.add(host);names.add(name);adapter.notifyDataSetChanged();progress.setVisibility(View.GONE);}
                        });
                    }
                });
            }
            public void onServiceLost(NsdServiceInfo info){}
        };
        nsdManager.discoverServices(SVC_TYPE,NsdManager.PROTOCOL_DNS_SD,discListener);
    }
    private void openPairing(String host){
        startActivity(new Intent(this,PairingActivity.class).putExtra(PairingActivity.EXTRA_HOST,host));
    }
    @Override protected void onDestroy(){
        super.onDestroy();
        try{if(discListener!=null)nsdManager.stopServiceDiscovery(discListener);}catch(Exception ignored){}
    }
}
