package com.isthatfreeproxysafe.ciao;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.app.ProgressDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.app.AlertDialog;
import android.os.Bundle;
import android.support.v7.widget.SwitchCompat;
import android.text.Editable;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import org.json.simple.parser.JSONParser;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertNotNull;

public class ActivityMain extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Main";

    private SwitchCompat swEnabled;
    private Spinner proxyCountryList;
    private Spinner proxySetting;
    private TextView proxyListText;
    private Button proxyApplySetting;
    private CheckBox manualProxyInsert;

    private AlertDialog dialogDoze = null;

    private static final int REQUEST_VPN = 1;

    private static final int MIN_SDK = Build.VERSION_CODES.ICE_CREAM_SANDWICH;

    public static final String ACTION_RULES_CHANGED = "com.isthatfreeproxysafe.ciao.ACTION_RULES_CHANGED";
    public static final String ACTION_QUEUE_CHANGED = "com.isthatfreeproxysafe.ciao.ACTION_QUEUE_CHANGED";
    public static final String EXTRA_APPROVE = "Approve";
    public static final String EXTRA_SIZE = "Size";

    // OAK----
    private List<ProxyServerCountryInfo> countryInfoList = new ArrayList<>();
    public static final int MAX_NUM_PROXIES = 4;
    public static final String ACTION_PROXY_LIST_CHANGED = "PROXY_LIST_CHANGED";

    private ArrayList<ProxyServerInfo> proxyList = new ArrayList<>();
    private List<ProxyServerInfo> httpProxyList = new LinkedList<>();
    private List<ProxyServerInfo> httpsProxyList = new LinkedList<>();
    private List<ProxyServerInfo> fullHttpProxyList = new LinkedList<>();
    private List<ProxyServerInfo> fullHttpsProxyList = new LinkedList<>();

    private ProxySetting current_proxy_setting = null;

    private ArrayAdapter<String> countrySpinnerAdapter;
    private ArrayAdapter<String> proxyTypeSpinnerAdapter;
    private ProgressDialog dialog;

    ServiceSinkhole mService;
    boolean mBound = false;


    // -------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this));
        Util.logExtras(getIntent());

        new ActivityAgreement(this).show();

        dialog = new ProgressDialog(ActivityMain.this);
        dialog.setCancelable(false);

        if (Build.VERSION.SDK_INT < MIN_SDK) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.android);
            return;
        }

        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);


        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean enabled = prefs.getBoolean("enabled", false);

        if (!getIntent().hasExtra(EXTRA_APPROVE)) {
            if (enabled)
                ServiceSinkhole.start("UI", this);
            else
                ServiceSinkhole.stop("UI", this);
        }

        // Action bar
        final View actionView = getLayoutInflater().inflate(R.layout.actionmain, null, false);
        swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);

        // OAK -------
        proxyCountryList = (Spinner) findViewById(R.id.proxy_country_spinner);
        proxySetting = (Spinner) findViewById(R.id.proxy_setting_spinner);
        proxyApplySetting = (Button) findViewById(R.id.proxy_apply_setting);
        proxyListText = (TextView) findViewById(R.id.proxy_list);
        proxyListText.setText("", TextView.BufferType.EDITABLE);
        //proxyPerfText = (TextView) findViewById(R.id.proxy_perf_display);
        //proxyPerfText.setText("", TextView.BufferType.EDITABLE);

        manualProxyInsert = (CheckBox) findViewById(R.id.manual_proxy_checkbox);
        final EditText httpProxyInput = (EditText) findViewById(R.id.http_proxy_input);
        final EditText httpsProxyInput = (EditText) findViewById(R.id.https_proxy_input);
        manualProxyInsert.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                httpProxyInput.getText().clear();
                httpsProxyInput.getText().clear();
                httpProxyInput.setVisibility(b ? View.VISIBLE : View.GONE);
                httpsProxyInput.setVisibility(b ? View.VISIBLE : View.GONE);

                proxySetting.setEnabled(!b);
                proxyCountryList.setEnabled(!b);
            }
        });

        /*final Button proxyPerfDisplay = (Button) findViewById(R.id.proxy_perf);
        proxyPerfDisplay.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Editable proxyEditableText = (Editable) proxyPerfText.getText();
                proxyEditableText.clear();
                proxyEditableText.append("# Retries : # Errors : Delays : # Recv\n");
                proxyEditableText.append("HTTP Proxy : "+Arrays.toString(mService.jni_get_proxy_perf(1))+"\n");
                proxyEditableText.append("HTTPs Proxy : "+Arrays.toString(mService.jni_get_proxy_perf(0))+"\n");
                proxyEditableText.append("Currently Active Packets : "+Arrays.toString(mService.jni_get_proxy_stats())+"\n");
                proxyEditableText.append("Session ID: " + ProxyUtil.getSessionId() +"\n");
                proxyEditableText.append("Enabled ID: " + ProxyUtil.getEnableId() +"\n");

            }
        });*/

        proxyApplySetting.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // If the user manually specified the proxy, then use it
                if(httpProxyInput.getText().toString().isEmpty() != httpsProxyInput.getText().toString().isEmpty()){
                    Toast.makeText(ActivityMain.this, "Please insert both proxies", Toast.LENGTH_LONG).show();
                    return;
                }

                if(!httpProxyInput.getText().toString().isEmpty()) {

                    ArrayList<ProxyServerInfo> manualProxies = new ArrayList<>();

                    // https://stackoverflow.com/questions/8204271/how-to-extract-ipport-from-strings-java?rq=1
                    String pattern = "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})";
                    Pattern p = Pattern.compile(pattern);
                    Matcher m1 = p.matcher(httpProxyInput.getText().toString());
                    Matcher m2 = p.matcher(httpsProxyInput.getText().toString());
                    if (!m1.matches() || !m2.matches()) {
                        Toast.makeText(ActivityMain.this, "Malformed IP address", Toast.LENGTH_LONG).show();
                        return;
                    }
                    Log.d(TAG, "OAK: manual proxy ip: "+m1.group(1)+":"+m1.group(2)+", "+m2.group(1)+":"+m2.group(2));
                    manualProxies.add(new ProxyServerInfo(m1.group(1), Integer.valueOf(m1.group(2)), false, true));
                    manualProxies.add(new ProxyServerInfo(m2.group(1), Integer.valueOf(m2.group(2)), true, true));
                    Intent in = new Intent();
                    in.setAction(ACTION_PROXY_LIST_CHANGED);
                    in.putParcelableArrayListExtra("ProxyList", manualProxies);
                    sendBroadcast(in);

                    proxyListText.clearComposingText();
                    Editable proxyEditableText = (Editable) proxyListText.getText();
                    proxyEditableText.clear();
                    String proxyListString = "";
                    for(ProxyServerInfo psi : manualProxies) {
                        proxyListString = proxyListString.concat(psi.toString()+"\n");
                    }
                    proxyEditableText.append(proxyListString);
                    return;
                }

                try {
                    // Fetch a list of proxies
                    String proxyType = proxySetting.getSelectedItem().toString();

                    Context context = getApplicationContext();
                    String country = proxyCountryList.getSelectedItem().toString();
                    String region = null;
                    if(country.contains(getText(R.string.locale_not_specified)))
                    {
                        Log.d(TAG, "Select no preference for countries");

                    } else {

                        for(ProxyServerCountryInfo ci : countryInfoList) {
                            if(country.contains(ci.getCountryName())) {
                                region = ci.getCountryCode();
                                break;
                            }
                        }
                    }

                    ProxySetting setting = new ProxySetting(proxyType, region, context);
                    Log.d(TAG, "Query is: "+setting.toQueryString());
                    new FetchProxyList(setting).execute();
                    //fetchProxy(setting, false, false);
                } catch(Exception e) {
                    //TODO:??
                    e.printStackTrace();
                }
            }
        });

        proxyTypeSpinnerAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item);
        proxyTypeSpinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        proxySetting.setAdapter(proxyTypeSpinnerAdapter);

        countrySpinnerAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item);
        countrySpinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        proxyCountryList.setAdapter(countrySpinnerAdapter);
        proxyCountryList.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                String selectedCountry = proxyCountryList.getSelectedItem().toString();
                int numTotalAny = 0, numTotalElite = 0, numTotalAnonymous = 0, numTotalTransparent = 0;
                for(ProxyServerCountryInfo ci : countryInfoList) {
                    String cname = ci.getCountryName()+" ("+ci.getNumAny()+")";
                    if(cname.equals(selectedCountry)) {
                        numTotalAny = ci.getNumAny();
                        numTotalElite = ci.getNumElite();
                        numTotalAnonymous = ci.getNumAnonymous();
                        numTotalTransparent = ci.getNumTransparent();
                        break;
                    } else {
                        numTotalAny += ci.getNumAny();
                        numTotalElite += ci.getNumElite();
                        numTotalAnonymous += ci.getNumAnonymous();
                        numTotalTransparent += ci.getNumTransparent();
                    }
                }

                proxyTypeSpinnerAdapter.clear();
                proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_any)+" ("+ numTotalAny+")");
                if(numTotalTransparent != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_transparent)+" ("+numTotalTransparent+")");
                if(numTotalAnonymous != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_anonymous)+" ("+numTotalAnonymous+")");
                if(numTotalElite != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_elite)+" ("+numTotalElite+")");
                proxyTypeSpinnerAdapter.notifyDataSetChanged();

            }

            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {

            }
        });


        // Bind to LocalService
        Intent intent = new Intent(this, ServiceSinkhole.class);
        bindService(intent, mConnection, Context.BIND_AUTO_CREATE);

        //-----------------------------

        // On/off switch
        swEnabled.setChecked(enabled);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                Log.i(TAG, "Switch=" + isChecked);
                prefs.edit().putBoolean("enabled", isChecked).apply();

                if (isChecked) {
                    try {
                        final Intent prepare = VpnService.prepare(ActivityMain.this);
                        if (prepare == null) {
                            Log.i(TAG, "Prepare done");
                            onActivityResult(REQUEST_VPN, RESULT_OK, null);
                        } else {
                            startActivityForResult(prepare, REQUEST_VPN);
                        }


                        ProxyUtil.generateSessionId();
                        new FetchProxyCountryList().execute();
                        new FetchProxyList(new ProxySetting(getApplicationContext())).execute();
                        // Reset spinners
                        proxyCountryList.setSelection(0);
                        proxySetting.setSelection(0);
                    } catch (Throwable ex) {
                        // Prepare failed
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        prefs.edit().putBoolean("enabled", false).apply();
                    }

                } else {
                    ServiceSinkhole.stop("switch off", ActivityMain.this);
                    Intent in = new Intent();
                    in.setAction(ACTION_PROXY_LIST_CHANGED);
                    in.putParcelableArrayListExtra("ProxyList", new ArrayList<ProxyServerInfo>());
                    sendBroadcast(in);

                    proxyCountryList.setVisibility(View.GONE);
                    proxySetting.setVisibility(View.GONE);
                    proxyListText.setVisibility(View.GONE);
                    manualProxyInsert.setVisibility(View.GONE);
                    proxyApplySetting.setVisibility(View.GONE);

                    // Need this so that the next time it is switched on, it queries the new list.
                    current_proxy_setting = null;
                }
            }
        });

        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        // Disabled warning
        TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);

        // Re-fetch country info if VPN is already enabled
        if(enabled) {
            ProxyUtil.generateSessionId();
            new FetchProxyCountryList().execute();
            new FetchProxyList(new ProxySetting(getApplicationContext())).execute(); // By default..
        }

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

    }

    /** Defines callbacks for service binding, passed to bindService() */
    private ServiceConnection mConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className,
                                       IBinder service) {
            // We've bound to LocalService, cast the IBinder and get LocalService instance
            ServiceSinkhole.LocalBinder binder = (ServiceSinkhole.LocalBinder) service;
            mService = binder.getService();
            mBound = true;
            Log.d(TAG, "Service is bound");
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            mBound = false;
        }
    };


    @Override
    protected void onResume() {
        Log.i(TAG, "Resume");

        super.onResume();
    }

    @Override
    protected void onPause() {
        Log.i(TAG, "Pause");
        super.onPause();
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        if (Build.VERSION.SDK_INT < MIN_SDK) {
            super.onDestroy();
            return;
        }
        //adapter = null;

        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this);

        if (dialogDoze != null) {
            dialogDoze.dismiss();
            dialogDoze = null;
        }

        // Unbind from the service
        if (mBound) {
            unbindService(mConnection);
            mBound = false;
        }

        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));
        Util.logExtras(data);

        if (requestCode == REQUEST_VPN) {
            // Handle VPN approval
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", resultCode == RESULT_OK).apply();
            if (resultCode == RESULT_OK) {
                ServiceSinkhole.start("prepared", this);

                //Toast on = Toast.makeText(ActivityMain.this, R.string.msg_on, Toast.LENGTH_LONG);
                //on.setGravity(Gravity.CENTER, 0, 0);
                //on.show();

                //checkDoze();
            } else if (resultCode == RESULT_CANCELED)
                Toast.makeText(this, R.string.msg_vpn_cancelled, Toast.LENGTH_LONG).show();

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Preference " + name + "=" + prefs.getAll().get(name));
        if ("enabled".equals(name)) {
            // Get enabled
            boolean enabled = prefs.getBoolean(name, false);

            // Display disabled warning
            TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
            tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);

            // Check switch state
            SwitchCompat swEnabled = (SwitchCompat) getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != enabled)
                swEnabled.setChecked(enabled);

        }
    }
    public static int MAX_URL_FETCH_RETRIES = 3;
    public static int URL_FETCH_TIMEOUT = 5000; // 5 secs

    org.json.simple.JSONObject fetch_and_parse_data(String path, int num_retries, int timeout) {

        org.json.simple.JSONObject jsonObject = null;
        for(int i=0; i<num_retries; i++) {
            try {
                Log.d(TAG, "Fetching "+path);
                URL url = new URL(path);
                URLConnection conn = url.openConnection();
                conn.setReadTimeout(timeout);
                BufferedInputStream in = new BufferedInputStream(conn.getInputStream());

                Log.d(TAG, "Successfuly received data");

                JSONParser jsonParser = new JSONParser();
                jsonObject = (org.json.simple.JSONObject) jsonParser.parse(new InputStreamReader(in, "UTF-8"));

                break;
            } catch(SocketTimeoutException | SocketException ste) {
                Log.d(TAG, "Fetching failed. Retrying " + i + "/" + MAX_URL_FETCH_RETRIES);
            } catch(Exception e) {
                e.printStackTrace();
                return null;
            }
        }
        return jsonObject;
    }

    private class FetchFullProxyListTask extends AsyncTask<Void, Void, List<ProxyServerInfo>> {

        String query;
        boolean fetchHttps;

        public FetchFullProxyListTask(String query, boolean fetchHttps) {
            this.query = query;
            this.fetchHttps = fetchHttps;
        }

        @Override
        protected List<ProxyServerInfo> doInBackground(Void... v) {

            // Generate new enabled_id
            ProxyUtil.generateEnableId();

            String urlString = ProxyWebAPI.HTTPS_QUERY_URL +"?strategy=6";
            if (query != null && !query.isEmpty()) {
                urlString = ProxyWebAPI.HTTPS_QUERY_URL + "?" + query;
            }
            if(fetchHttps) {
                urlString += "&protocol=https";
            }
            Log.d(TAG, "Fetching URL: " + urlString);

            List<ProxyServerInfo> fullProxyList = new LinkedList<>();

            org.json.simple.JSONObject jsonObject = fetch_and_parse_data(urlString, MAX_URL_FETCH_RETRIES, URL_FETCH_TIMEOUT);

            if (jsonObject == null) {
                Log.e(TAG, "JsonObject is null");
                return fullProxyList;
            }

            // Only use up to MAX_NUM_PROXIES proxies at a time
            int listSize = jsonObject.size();

            for (int i = 0; i < listSize; i++) {

                org.json.simple.JSONObject proxyObj = (org.json.simple.JSONObject) jsonObject.get(i + "");

                String ip = (String) proxyObj.get("ip");
                String port = (String) proxyObj.get("port");

                ProxyServerInfo psi = new ProxyServerInfo(ip, Integer.parseInt(port), fetchHttps);
                fullProxyList.add(psi);
            }
            return fullProxyList;
        }
    }


    private class FetchProxyList extends AsyncTask<Void, String, Void> {

        ProxySetting setting;
        boolean changeHttpProxy = false;
        boolean changeHttpsProxy = false;

        public FetchProxyList(ProxySetting ps) {
            this(ps, false, false);
        }

        // Set both flags to false uses our heuristic to change proxies
        public FetchProxyList(ProxySetting ps, boolean changeHttp, boolean changeHttps) {
            setting = new ProxySetting(ps);
            changeHttpsProxy = changeHttps;
            changeHttpProxy = changeHttp;
        }


        private List<ProxyServerInfo> getFullProxyList(boolean fetchHttps, String... query) {

            // Generate new enabled_id
            ProxyUtil.generateEnableId();

            String urlString = ProxyWebAPI.HTTPS_QUERY_URL +"?strategy=6";
            if (query != null && query.length > 0 && !query[0].isEmpty()) {
                urlString = ProxyWebAPI.HTTPS_QUERY_URL + "?" + query[0];
            }
            if(fetchHttps) {
                urlString += "&protocol=https";
            }
            Log.d(TAG, "Fetching URL: " + urlString);

            List<ProxyServerInfo> fullProxyList = new LinkedList<>();

            org.json.simple.JSONObject jsonObject = fetch_and_parse_data(urlString, MAX_URL_FETCH_RETRIES, URL_FETCH_TIMEOUT);

            if (jsonObject == null) {
                Log.e(TAG, "JsonObject is null");
                return fullProxyList;
            }

            // Only use up to MAX_NUM_PROXIES proxies at a time
            int listSize = jsonObject.size();

            for (int i = 0; i < listSize; i++) {

                org.json.simple.JSONObject proxyObj = (org.json.simple.JSONObject) jsonObject.get(i + "");

                String ip = (String) proxyObj.get("ip");
                String port = (String) proxyObj.get("port");

                ProxyServerInfo psi = new ProxyServerInfo(ip, Integer.parseInt(port), fetchHttps);
                fullProxyList.add(psi);
            }
            return fullProxyList;
        }

        // Perform probing and return up to N probed proxies
        private List<ProxyServerInfo> probeProxy(List<ProxyServerInfo> fullProxyList, int N, int max_wait_time) {
            List<ProxyServerInfo> probedProxyList = new LinkedList<>();
            final List<Boolean> probedSuccess = new LinkedList<>();
            N = Math.min(N, fullProxyList.size());
            final List<Socket> sockets = new ArrayList<>();
            final CountDownLatch latch = new CountDownLatch(1);
            for(int i=0; i<N; i++) {
                final ProxyServerInfo psi = fullProxyList.get(i);
                probedProxyList.add(psi);
                probedSuccess.add(Boolean.FALSE);
                try {
                    sockets.add(SocketChannel.open().socket());
                } catch (Exception e) {
                    Log.e(TAG, "Can't open a socket");
                    continue;
                }
                final int idx = i;
                Thread t = new Thread(new Runnable(){
                    @Override
                    public void run() {
                        try {
                            Log.d(TAG, "OAK: perform probing on proxy; " + psi.toString());

                            long requestTime = System.currentTimeMillis();
                            Socket s = sockets.get(idx);
                            if (null == s) {
                                Log.e(TAG, "Cannot create a new socket..");
                                return;
                            }
                            if (null != mService) mService.protect(s);

                            s.connect(new InetSocketAddress(psi.addr, psi.port));

                            PrintWriter pw = new PrintWriter(s.getOutputStream());
                            pw.println("GET " + ProxyWebAPI.TEST_URL + " HTTP/1.1");
                            pw.println("Host: " + ProxyWebAPI.WEB_API_DOMAINNAME);
                            pw.println();
                            pw.flush();
                            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
                            String response = br.readLine();
                            br.close();
                            s.close();
                            long downloadTime = System.currentTimeMillis() - requestTime;
                            Log.d(TAG, psi + " response: " + response + " in " + downloadTime + " ms");
                            if (response.contains(HttpURLConnection.HTTP_OK + "")) {
                                probedSuccess.set(idx, Boolean.TRUE);

                                Thread.sleep(downloadTime);
                                latch.countDown();
                            }
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
                t.start();
            }
            try {
                latch.await();
                for(Socket s : sockets) {
                    if(!s.isClosed()) s.close();
                }
                Thread.sleep(1000); // Just in case
            } catch(Exception e) {
                e.printStackTrace();
            }
            List<ProxyServerInfo> pass = new ArrayList<>();
            for(int i=0; i<N; i++) {
                Boolean success = probedSuccess.get(i);
                if(success != null && success == Boolean.TRUE) {
                    pass.add(probedProxyList.get(i));
                    Log.d(TAG, probedProxyList.get(i) + " passed!");
                }
            }
            return pass;
        }

        private List<ProxyServerInfo> purgeSlowProxies(List<ProxyServerInfo> fullProxyList, List<ProxyServerInfo> probedProxy, int N) {
            List<ProxyServerInfo> out_fpl = new ArrayList<>();

            // Add responsive probed proxies into the new list upto N proxies
            for(int i=0; i<N; i++) {
                if(probedProxy.contains(fullProxyList.get(i))) out_fpl.add(fullProxyList.get(i));
            }

            // Add the rest (unprobed proxies)
            for(int i=N; i<fullProxyList.size(); i++) {
                out_fpl.add(fullProxyList.get(i));
            }

            return out_fpl;
        }
        @Override
        protected void onPreExecute() {
            if(!dialog.isShowing()) {
                dialog.setTitle("CIAO");
                dialog.setMessage("Testing Proxy");
                dialog.setCancelable(false);
                final FetchProxyList cur = this;
                dialog.setButton(DialogInterface.BUTTON_NEGATIVE, "Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                        cur.cancel(true);
                        PreferenceManager.getDefaultSharedPreferences(ActivityMain.this).edit().putBoolean("enabled", false).apply();
                    }
                });

                dialog.show();
            }
        }

        @Override
        protected void onPostExecute(Void v) {

            if (dialog.isShowing()) {
                dialog.dismiss();
            }

            if(httpProxyList == null || httpsProxyList == null) {
                Log.e(TAG, "How come the proxy lists are either null or empty?");
                return;
            }

            proxyList.clear();
            if(!httpProxyList.isEmpty()) proxyList.add(httpProxyList.get(0));
            else if(!httpsProxyList.isEmpty()) proxyList.add(httpsProxyList.get(0));
            if(!httpsProxyList.isEmpty()) proxyList.add(httpsProxyList.get(0));
            else if(!httpProxyList.isEmpty()) proxyList.add(httpProxyList.get(0));

            // On Success
            // (1) Broadcast the list to ServiceSinkhole
            // (2) Display the list
            // (3) Set visibility of the proxy list, country list, proxy type and apply setting button

            // For probing strategy, only send the top proxy
            // Broadcast the proxy list
            Intent in = new Intent();
            in.setAction(ACTION_PROXY_LIST_CHANGED);
            Log.d(TAG, "Current HTTP proxy list: "+Arrays.toString(httpProxyList.toArray()));
            Log.d(TAG, "Current full HTTP proxy list: "+Arrays.toString(fullHttpProxyList.toArray()));
            Log.d(TAG, "Current HTTPs proxy list: "+Arrays.toString(httpsProxyList.toArray()));
            Log.d(TAG, "Current full HTTPs proxy list: "+Arrays.toString(fullHttpsProxyList.toArray()));
            Log.d(TAG, "Sending proxy list: "+Arrays.toString(proxyList.toArray()));
            in.putParcelableArrayListExtra("ProxyList", proxyList);
            sendBroadcast(in);

            proxyListText.clearComposingText();
            Editable proxyEditableText = (Editable) proxyListText.getText();
            proxyEditableText.clear();
            for(int i=0; i<proxyList.size(); i++) {
                proxyEditableText.append(proxyList.get(i).toString()+"\n");
            }
            if(proxyList.isEmpty()) proxyEditableText.append("No Proxy is available :(\n");

            if(proxyListText.getVisibility() != View.VISIBLE) proxyListText.setVisibility(View.VISIBLE);
            if(proxyCountryList.getVisibility() != View.VISIBLE) proxyCountryList.setVisibility(View.VISIBLE);
            if(proxySetting.getVisibility() != View.VISIBLE) proxySetting.setVisibility(View.VISIBLE);
            if(proxyApplySetting.getVisibility() != View.VISIBLE) proxyApplySetting.setVisibility(View.VISIBLE);
            if(manualProxyInsert.getVisibility() != View.VISIBLE) manualProxyInsert.setVisibility(View.VISIBLE);
        }

        @Override
        protected Void doInBackground(Void... v) {
            // If it's different query than the previous one, always discard all proxies list
            // (Regardless of the flags changeHttpProxy and changeHttpsProxy
            // Otherwise, if either of the flags is true, the flags take over the change
            // Otherwise, we use heuristic to change the proxy
            if(!setting.sameConfig(current_proxy_setting)) {
                httpProxyList.clear();
                fullHttpProxyList.clear();
                httpsProxyList.clear();
                fullHttpsProxyList.clear();

                if(current_proxy_setting == null)
                    Log.d(TAG, "Reset the proxy lists current proxy setting is null vs "+setting.toConfigString());
                else
                    Log.d(TAG, "Reset the proxy lists since proxy config is different: "+current_proxy_setting.toConfigString()+" vs "+setting.toConfigString());

                changeHttpProxy = true;
                changeHttpsProxy = true;
            } else if(!changeHttpProxy && !changeHttpsProxy) {
                if(httpsProxyList.isEmpty() && !httpProxyList.isEmpty()) {
                    // Special case where https proxy does not exist
                    // no choice but to change http proxy...
                    changeHttpProxy = true;
                } else {
                    // # retries | # errors | total delays | s# recv
                    float[] httpProxyPerf = mService.jni_get_proxy_perf(1);
                    float[] httpsProxyPerf = mService.jni_get_proxy_perf(0);

                    // Heuristic:
                    // (1) if average delay of http or https proxy >= .5 secs or stddev >= 1, change that proxy
                    // (2) else, change the proxy that has higher number of errors
                    // (3) If tied, return the one that has higher number of retransmissions
                    if (httpProxyPerf[1] > httpsProxyPerf[1]) changeHttpProxy = true;
                    else if (httpProxyPerf[1] < httpsProxyPerf[1]) changeHttpsProxy = true;
                    else { // Tie break using number of retransmissions
                        if (httpsProxyPerf[0] < httpProxyPerf[0]) changeHttpProxy = true;
                        else changeHttpsProxy = true;
                    }
                    changeHttpProxy |= (httpProxyPerf[2] >= .5) || (httpProxyPerf[3] >= 1);
                    changeHttpsProxy |= ( httpsProxyPerf[2] >= .5) || (httpsProxyPerf[3] >= 1);
                }
            } else { } // Otherwise, let the user specify the change

            Log.d(TAG, "OAK: change http proxy: "+changeHttpProxy+" change https proxy: "+changeHttpsProxy);

            // Save the proxy setting
            current_proxy_setting = new ProxySetting(setting);

            int MAX_WAIT_TIME = 5000;
            // First check if there's any probed proxy left after discarding the current one
            // If there is, remove the top one and return
            // Else re-do the probing step
            if(changeHttpProxy) {
                if (httpProxyList.size() - 1 > 0) {
                    Log.d(TAG, "Remove the current HTTP proxy");
                    ProxyServerInfo p1 = httpProxyList.remove(0);
                    ProxyServerInfo p2 = fullHttpProxyList.remove(0);
                    if (!p1.toString().equals(p2.toString())) {
                        Log.e(TAG, "OAK: Trying to change proxy but the top HTTP proxies are different: " + p1.toString() + " vs " + p2.toString());
                    }
                } else {
                    // Remove the top one
                    if (httpProxyList.size() == 1) {
                        ProxyServerInfo p1 = httpProxyList.remove(0);
                        ProxyServerInfo p2 = fullHttpProxyList.remove(0);
                        if (!p1.toString().equals(p2.toString())) {
                            Log.e(TAG, "OAK: Trying to change proxy but the top HTTP proxies are different: " + p1.toString() + " vs " + p2.toString());
                        }
                    }
                    // If the full list is empty after discarding the current one, re-fetch the list
                    if (fullHttpProxyList.size() == 0) {
                        fullHttpProxyList = getFullProxyList(false, setting.toQueryString());
                    }
                    Log.d(TAG, "Full HTTP list before probing: " + Arrays.toString(fullHttpProxyList.toArray()));

                    while(httpProxyList.isEmpty() && !fullHttpProxyList.isEmpty()) {
                        int probeSize = Math.min(fullHttpProxyList.size(), ActivityMain.MAX_NUM_PROXIES);
                        httpProxyList = probeProxy(fullHttpProxyList, ActivityMain.MAX_NUM_PROXIES, MAX_WAIT_TIME);
                        fullHttpProxyList = purgeSlowProxies(fullHttpProxyList, httpProxyList, probeSize);
                    }
                    if(httpProxyList.isEmpty()) Log.e(TAG, "Http proxy list is empty :(");
                    // This function is needed cuz stupid java does not allow to return multiple lists and im too lazy to create struct
                    Log.d(TAG, "HTTP probed list: " + Arrays.toString(httpProxyList.toArray()));
                    Log.d(TAG, "Full HTTP list after probing: " + Arrays.toString(fullHttpProxyList.toArray()));
                }
            }

            // Ditto for HTTPs proxies
            if(changeHttpsProxy) {
                if (httpsProxyList.size() - 1 > 0) {
                    Log.d(TAG, "Remove the current HTTP proxy");
                    ProxyServerInfo p1 = httpsProxyList.remove(0);
                    ProxyServerInfo p2 = fullHttpsProxyList.remove(0);
                    if (!p1.toString().equals(p2.toString())) {
                        Log.e(TAG, "OAK: Trying to change proxy but the top HTTPs proxies are different: " + p1.toString() + " vs " + p2.toString());
                    }

                } else {
                    if (httpsProxyList.size() == 1) {
                        ProxyServerInfo p1 = httpsProxyList.remove(0);
                        ProxyServerInfo p2 = fullHttpsProxyList.remove(0);
                        if (!p1.toString().equals(p2.toString())) {
                            Log.e(TAG, "OAK: Trying to change proxy but the top HTTPs proxies are different: " + p1.toString() + " vs " + p2.toString());
                        }
                    }
                    if (fullHttpsProxyList.size() == 0) {
                        fullHttpsProxyList = getFullProxyList(true, setting.toQueryString());
                    }
                    Log.d(TAG, "Full HTTPs list before probing: " + Arrays.toString(fullHttpsProxyList.toArray()));

                    while(httpsProxyList.isEmpty() && !fullHttpsProxyList.isEmpty()) {
                        int probeSize = Math.min(fullHttpsProxyList.size(), ActivityMain.MAX_NUM_PROXIES);
                        httpsProxyList = probeProxy(fullHttpsProxyList, probeSize, MAX_WAIT_TIME);
                        fullHttpsProxyList = purgeSlowProxies(fullHttpsProxyList, httpsProxyList, probeSize);
                    }
                    if(httpsProxyList.isEmpty()) Log.e(TAG, "Https proxy list is empty :(");
                    Log.d(TAG, "HTTPs probed list: " + Arrays.toString(httpsProxyList.toArray()));
                    Log.d(TAG, "Full HTTPs list after probing: " + Arrays.toString(fullHttpsProxyList.toArray()));
                }
            }
            return null;
        }
    };



    private class FetchProxyCountryList extends AsyncTask<Void, Void, ArrayList<ProxyServerCountryInfo>> {


        @Override
        protected void onPostExecute(final ArrayList<ProxyServerCountryInfo> countryInfos) {

            if(countryInfos == null) {
                return;
            }

            // Reset the list
            countryInfoList.clear();
            countryInfoList.addAll(countryInfos);

            // Get a list of country names and total number of proxies
            int numTotalAny = 0, numTotalElite = 0, numTotalAnonymous = 0, numTotalTransparent = 0;
            List<String> countryNames = new ArrayList<>(countryInfos.size());
            for(ProxyServerCountryInfo cinfo : countryInfos) {
                numTotalAny += cinfo.getNumAny();
                numTotalElite += cinfo.getNumElite();
                numTotalAnonymous += cinfo.getNumAnonymous();
                numTotalTransparent += cinfo.getNumTransparent();
                countryNames.add(cinfo.getCountryName()+" ("+cinfo.getNumAny()+")");
            }
            // Sort the list alphabetically
            Collections.sort(countryNames);

            // Display a list of countries - starting with Not Specified (XXX) then countries listed alphabetically
            countrySpinnerAdapter.clear();
            countrySpinnerAdapter.insert(getText(R.string.locale_not_specified)+" ("+numTotalAny+")", 0);
            for(int i=0; i<countryNames.size(); i++) countrySpinnerAdapter.insert(countryNames.get(i), i+1);
            countrySpinnerAdapter.notifyDataSetChanged();

            // Display proxy types (Any, Transparent, Anonymous or Elite)
            proxyTypeSpinnerAdapter.clear();
            if(numTotalAny != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_any)+" ("+numTotalAny+")");
            if(numTotalTransparent != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_transparent)+" ("+numTotalTransparent+")");
            if(numTotalAnonymous != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_anonymous)+" ("+numTotalAnonymous+")");
            if(numTotalElite != 0) proxyTypeSpinnerAdapter.add(getText(R.string.proxy_type_elite)+" ("+numTotalElite+")");
            proxyTypeSpinnerAdapter.notifyDataSetChanged();

            // That is it.
        }

        @Override
        protected ArrayList<ProxyServerCountryInfo> doInBackground(Void... param) {

            org.json.simple.JSONObject jsonObject = null;

            jsonObject = fetch_and_parse_data(ProxyWebAPI.DEFAULT_COUNTRY_QUERY_URL + "?strategy=2",
                    MAX_URL_FETCH_RETRIES, URL_FETCH_TIMEOUT);

            if(jsonObject == null) {
                Log.e(TAG, "JsonObject is null. Maybe the internet is down?");
                return null;
            }

            int numCountries = jsonObject.size();

            ArrayList<ProxyServerCountryInfo> output = new ArrayList<>(numCountries);
            for(int i=0; i<numCountries; i++) {
                org.json.simple.JSONObject obj = (org.json.simple.JSONObject) jsonObject.get(i+"");

                String code = (String) obj.get("code");
                int numAny = 0, numAnonymous = 0, numElite = 0, numTransparent = 0;
                if((obj.get("any")).equals("True")) numAny = Integer.parseInt((String) obj.get("num_any"));
                if((obj.get("anonymous")).equals("True")) numAnonymous = Integer.parseInt((String) obj.get("num_anonymous"));
                if((obj.get("elite")).equals("True")) numElite = Integer.parseInt((String) obj.get("num_elite"));
                if((obj.get("transparent")).equals("True")) numTransparent = Integer.parseInt((String) obj.get("num_transparent"));

                output.add(new ProxyServerCountryInfo(code, numAny, numAnonymous, numElite, numTransparent));
            }

            Log.d(TAG, "Country List: "+ Arrays.toString(output.toArray()));
            return output;
        }
    };
}
