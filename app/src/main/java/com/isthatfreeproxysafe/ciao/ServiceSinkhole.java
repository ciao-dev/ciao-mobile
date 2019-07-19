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

import android.annotation.TargetApi;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.util.Log;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class ServiceSinkhole extends VpnService implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Service";


    // Binder given to clients
    private final IBinder mBinder = new LocalBinder();

    /**
     * Class used for the client Binder.  Because we know this service always
     * runs in the same process as its clients, we don't need to deal with IPC.
     */
    public class LocalBinder extends Binder {
        ServiceSinkhole getService() {
            // Return this instance of LocalService so clients can call public methods
            return ServiceSinkhole.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }


    private boolean registeredProxyList = false;
    private boolean registeredUser = false;
    private boolean registeredIdleState = false;
    private boolean registeredConnectivityChanged = false;

    private State state = State.none;
    private boolean user_foreground = true;
    private boolean last_connected = false;
    private ServiceSinkhole.Builder last_builder = null;
    private ParcelFileDescriptor vpn = null;

    private long last_hosts_modified = 0;
    private Map<String, Boolean> mapHostsBlocked = new HashMap<>();
    private Map<Integer, Boolean> mapUidAllowed = new HashMap<>();
    private Map<Integer, Integer> mapUidKnown = new HashMap<>();
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    public static final int NOTIFY_DOWNLOAD = 9;

    // OAK ------
    private List<ProxyServerInfo> httpProxyList = null;
    private List<ProxyServerInfo> httpsProxyList = null;
    private int httpProxyIdx = 0;
    private int httpsProxyIdx = 0;

    // ----------

    private volatile Looper commandLooper;
    private volatile Looper logLooper;
    private volatile Looper statsLooper;
    private volatile Looper proxyUsageLooper;
    private volatile CommandHandler commandHandler;
    private volatile LogHandler logHandler;
    private volatile ProxyUsageHandler proxyUsageHandler;

    public static final String EXTRA_COMMAND = "Command";
    private static final String EXTRA_REASON = "Reason";
    public static final String EXTRA_NETWORK = "Network";
    public static final String EXTRA_UID = "UID";
    public static final String EXTRA_PACKAGE = "Package";
    public static final String EXTRA_BLOCKED = "Blocked";

    private static final int MSG_SERVICE_INTENT = 0;
    private static final int MSG_PACKET = 4;
    private static final int MSG_USAGE = 5;
    private static final int MSG_PROXY_USAGE = 6;
    private static final int MSG_SERVICE_STOP = 7;

    private enum State {none, waiting, enforcing}

    public enum Command {run, start, reload, stop, stats, set, householding, watchdog}

    private static volatile PowerManager.WakeLock wlInstance = null;

    private static final String ACTION_HOUSE_HOLDING = "com.isthatfreeproxysafe.ciao.HOUSE_HOLDING";
    private static final String ACTION_WATCHDOG = "com.isthatfreeproxysafe.ciao.WATCHDOG";

    private native void jni_init();

    private native void jni_start(int tun, boolean fwd53, int rcode, int loglevel);

    private native void jni_stop(int tun, boolean clr);

    private native int jni_get_mtu();

    public native int[] jni_get_stats();

    public native int[] jni_get_proxy_stats();

    private static native void jni_pcap(String name, int record_size, int file_size);

    private native void jni_socks5(String addr, int port, String username, String password);

    private native void jni_done();

    public native float[] jni_get_proxy_perf(int http);

    private native void jni_reset_proxy_perf(String ip, int port, int http);

    private native boolean jni_is_http_port(int port);

    private native boolean jni_is_https_port(int port);

    public static void setPcap(boolean enabled, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        int record_size = 64;
        try {
            String r = prefs.getString("pcap_record_size", null);
            if (TextUtils.isEmpty(r))
                r = "64";
            record_size = Integer.parseInt(r);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        int file_size = 2 * 1024 * 1024;
        try {
            String f = prefs.getString("pcap_file_size", null);
            if (TextUtils.isEmpty(f))
                f = "2";
            file_size = Integer.parseInt(f) * 1024 * 1024;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        File pcap = (enabled ? new File(context.getDir("data", MODE_PRIVATE), "com.isthatfreeproxysafe.ciao.pcap") : null);
        jni_pcap(pcap == null ? null : pcap.getAbsolutePath(), record_size, file_size);
    }

    private final class CommandHandler extends Handler {
        public int queue = 0;

        public CommandHandler(Looper looper) {
            super(looper);
        }

        private void reportQueueSize() {
            Intent ruleset = new Intent(ActivityMain.ACTION_QUEUE_CHANGED);
            ruleset.putExtra(ActivityMain.EXTRA_SIZE, queue);
            LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
        }

        public void queue(Intent intent) {
            synchronized (this) {
                queue++;
                reportQueueSize();
            }
            Message msg = commandHandler.obtainMessage();
            msg.obj = intent;
            msg.what = MSG_SERVICE_INTENT;
            commandHandler.sendMessage(msg);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                switch (msg.what) {
                    case MSG_SERVICE_INTENT:
                        handleIntent((Intent) msg.obj);
                        break;
                    default:
                        Log.e(TAG, "Unknown command message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            } finally {
                synchronized (this) {
                    queue--;
                    reportQueueSize();
                }
            }
        }

        private void handleIntent(Intent intent) {
            final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);

            Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
            String reason = intent.getStringExtra(EXTRA_REASON);
            Log.i(TAG, "Executing intent=" + intent + " command=" + cmd + " reason=" + reason +
                    " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

            // Check if foreground
            if (cmd != Command.stop)
                if (!user_foreground) {
                    Log.i(TAG, "Command " + cmd + "ignored for background user");
                    return;
                }

            // Watchdog
            if (cmd == Command.start || cmd == Command.reload) {
                Intent watchdogIntent = new Intent(ServiceSinkhole.this, ServiceSinkhole.class);
                watchdogIntent.setAction(ACTION_WATCHDOG);
                PendingIntent pi = PendingIntent.getService(ServiceSinkhole.this, 1, watchdogIntent, PendingIntent.FLAG_UPDATE_CURRENT);

                AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
                am.cancel(pi);

                int watchdog = Integer.parseInt(prefs.getString("watchdog", "0"));
                if (watchdog > 0) {
                    Log.i(TAG, "Watchdog " + watchdog + " minutes");
                    am.setInexactRepeating(AlarmManager.RTC, SystemClock.elapsedRealtime() + watchdog * 60 * 1000, watchdog * 60 * 1000, pi);
                }
            }

            try {
                switch (cmd) {
                    case run:
                        run();
                        break;

                    case start:
                        start();
                        break;

                    case reload:
                        reload();
                        break;

                    case stop:
                        stop();
                        break;

                    case householding:
                        householding(intent);
                        break;

                    case watchdog:
                        watchdog(intent);
                        break;

                    default:
                        Log.e(TAG, "Unknown command=" + cmd);
                }

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                if (cmd == Command.start || cmd == Command.reload) {
                    if (VpnService.prepare(ServiceSinkhole.this) == null) {
                        Log.w(TAG, "VPN not prepared connected=" + last_connected);
                        if (last_connected) {
                            //showAutoStartNotification();
                            /*if (!Util.isPlayStoreInstall(ServiceSinkhole.this))
                                showErrorNotification(ex.toString());*/
                        }
                        // Retried on connectivity change
                    } else {
                        //showErrorNotification(ex.toString());

                        // Disable firewall
                        prefs.edit().putBoolean("enabled", false).apply();
                        //WidgetMain.updateWidgets(ServiceSinkhole.this);
                    }
                } /*else
                    showErrorNotification(ex.toString());*/
            }
        }

        private void run() {
            if (state == State.none) {
                //startForeground(NOTIFY_WAITING, getWaitingNotification());
                state = State.waiting;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }
        }

        private void start() {
            if (vpn == null) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                //startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0, 0));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());

                List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);
                List<Rule> listAllowed = getAllowedRules(listRule);

                last_builder = getBuilder(listAllowed, listRule);
                vpn = startVPN(last_builder);
                if (vpn == null)
                    throw new IllegalStateException(getString((R.string.msg_start_failed)));

                startNative(vpn, listAllowed, listRule);

                //removeWarningNotifications();
                //updateEnforcingNotification(listAllowed.size(), listRule.size());
            }
        }

        private void reload() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean clear = prefs.getBoolean("clear_onreload", false);

            if (state != State.enforcing) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
               // startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0, 0));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }

            List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);
            List<Rule> listAllowed = getAllowedRules(listRule);
            ServiceSinkhole.Builder builder = getBuilder(listAllowed, listRule);

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) {
                last_builder = builder;
                Log.i(TAG, "Legacy restart");

                if (vpn != null) {
                    stopNative(vpn, clear);
                    stopVPN(vpn);
                    vpn = null;
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {
                    }
                }
                vpn = startVPN(last_builder);

            } else {
                if (vpn != null && prefs.getBoolean("filter", false) && builder.equals(last_builder)) {
                    Log.i(TAG, "Native restart");
                    stopNative(vpn, clear);

                } else {
                    last_builder = builder;
                    Log.i(TAG, "VPN restart");

                    // Attempt seamless handover
                    ParcelFileDescriptor prev = vpn;
                    vpn = startVPN(builder);

                    if (prev != null && vpn == null) {
                        Log.w(TAG, "Handover failed");
                        stopNative(prev, clear);
                        stopVPN(prev);
                        prev = null;
                        try {
                            Thread.sleep(3000);
                        } catch (InterruptedException ignored) {
                        }
                        vpn = startVPN(last_builder);
                        if (vpn == null)
                            throw new IllegalStateException("Handover failed");
                    }

                    if (prev != null) {
                        stopNative(prev, clear);
                        stopVPN(prev);
                    }
                }
            }

            if (vpn == null)
                throw new IllegalStateException(getString((R.string.msg_start_failed)));

            startNative(vpn, listAllowed, listRule);
            proxyUsageHandler.sendEmptyMessage(MSG_SERVICE_STOP);
        }

        private void stop() {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
                unprepare();
            }
            if (state == State.enforcing) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("show_stats", false)) {
                    //startForeground(NOTIFY_WAITING, getWaitingNotification());
                    state = State.waiting;
                    Log.d(TAG, "Start foreground state=" + state.toString());
                } else
                    state = State.none;
            }
            proxyUsageHandler.sendEmptyMessage(MSG_SERVICE_STOP);
        }

        private void householding(Intent intent) {
            // Keep log records for three days
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupLog(new Date().getTime() - 3 * 24 * 3600 * 1000L);

            // Clear expired DNS records
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupDns();
        }

        private void watchdog(Intent intent) {
            if (vpn == null) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("enabled", false)) {
                    Log.e(TAG, "Service was killed");
                    start();
                }
            }
        }

    }

    private final class ProxyUsageHandler extends Handler {
        public ProxyUsageHandler(Looper looper) {
            super(looper);
        }

        private JSONArray pUsageJson = new JSONArray();

        @Override
        public void handleMessage(Message msg) {
            try {

                switch (msg.what) {

                    case MSG_PROXY_USAGE:
                        proxyUsage((ProxyUsage) msg.obj);
                        break;

                    case MSG_SERVICE_STOP:
                        clear();
                        break;

                    default:
                        Log.e(TAG, "Unknown proxy usage message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private void proxyUsage(ProxyUsage usage) {

            JSONObject json = usage.toJsonObject(ServiceSinkhole.this);
            pUsageJson.add(json);
            Log.d(TAG, "Num ProxyUsage: "+pUsageJson.size());
            if(pUsageJson.size() >= ProxyUtil.MAX_PROXY_USAGE_SIZE) {
                clear();
            }
        }

        private void clear() {
            Log.d(TAG, "Clearing Proxy Usage Buffer");
            if(!pUsageJson.isEmpty()) {
                Log.d(TAG, "Sending v " + Util.getSelfVersionName(getApplicationContext()) + " Proxy Stats: "+pUsageJson.toString());
                if(!BuildConfig.DEBUG) {
                    new StatisticsReportTask(ProxyWebAPI.STATS_WEB_API_DOMAINNAME,
                            ProxyWebAPI.STATS_WEB_API_PATH + "?"+ProxyWebAPI.getVersion(getApplicationContext())).execute(pUsageJson.toString());
                }
                pUsageJson.clear();

            }
        }
    }

    private final class LogHandler extends Handler {
        public LogHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            try {

                switch (msg.what) {
                   /* case MSG_PACKET:
                        log((Packet) msg.obj, msg.arg1, msg.arg2 > 0);
                        break;*/

                    case MSG_USAGE:
                        usage((Usage) msg.obj);
                        break;

                    default:
                        Log.e(TAG, "Unknown log message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private void log(Packet packet, int connection, boolean interactive) {
            // Get settings
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean log = prefs.getBoolean("log", false);
            boolean log_app = prefs.getBoolean("log_app", false);

            DatabaseHelper dh = DatabaseHelper.getInstance(ServiceSinkhole.this);

            // Get real name
            String dname = dh.getQName(packet.uid, packet.daddr);

            // Traffic log
            if (log)
                dh.insertLog(packet, dname, connection, interactive);

            // Application log
            if (log_app && packet.uid >= 0 && !(packet.uid == 0 && packet.protocol == 17 && packet.dport == 53)) {
                if (!(packet.protocol == 6 /* TCP */ || packet.protocol == 17 /* UDP */))
                    packet.dport = 0;
                if (dh.updateAccess(packet, dname, -1)) {
                    lock.readLock().lock();
                   /* if (mapNoNotify.containsKey(packet.uid) && mapNoNotify.get(packet.uid))
                        showAccessNotification(packet.uid);*/
                    lock.readLock().unlock();
                }
            }
        }

        private void usage(Usage usage) {
            if (usage.Uid >= 0 && !(usage.Uid == 0 && usage.Protocol == 17 && usage.DPort == 53)) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                boolean filter = prefs.getBoolean("filter", true);
                boolean log_app = prefs.getBoolean("log_app", true);
                boolean track_usage = prefs.getBoolean("track_usage", true);
                if (filter && log_app && track_usage) {
                    DatabaseHelper dh = DatabaseHelper.getInstance(ServiceSinkhole.this);
                    String dname = dh.getQName(usage.Uid, usage.DAddr);
                    Log.i(TAG, "Usage account " + usage + " dname=" + dname);
                    //dh.updateUsage(usage, dname);
                }
            }
        }
    }
    public static List<InetAddress> getDns(Context context) {
        List<InetAddress> listDns = new ArrayList<>();
        List<String> sysDns = Util.getDefaultDNS(context, true);

        // Get custom DNS servers
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean ip6 = prefs.getBoolean("ip6", false);
        String vpnDns1 = prefs.getString("dns", null);
        String vpnDns2 = prefs.getString("dns2", null);
        Log.i(TAG, "DNS system=" + TextUtils.join(",", sysDns) + " VPN1=" + vpnDns1 + " VPN2=" + vpnDns2);

        if (vpnDns1 != null)
            try {
                InetAddress dns = InetAddress.getByName(vpnDns1);
                if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) &&
                        (ip6 || dns instanceof Inet4Address))
                    listDns.add(dns);
            } catch (Throwable ignored) {
            }

        if (vpnDns2 != null)
            try {
                InetAddress dns = InetAddress.getByName(vpnDns2);
                if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) &&
                        (ip6 || dns instanceof Inet4Address))
                    listDns.add(dns);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        // Use system DNS servers only when no two custom DNS servers specified
        if (listDns.size() <= 1)
            for (String def_dns : sysDns)
                try {
                    InetAddress ddns = InetAddress.getByName(def_dns);
                    if (!listDns.contains(ddns) &&
                            !(ddns.isLoopbackAddress() || ddns.isAnyLocalAddress()) &&
                            (ip6 || ddns instanceof Inet4Address))
                        listDns.add(ddns);
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        // Remove local DNS servers when not routing LAN
        boolean lan = prefs.getBoolean("lan", false);
        boolean use_hosts = prefs.getBoolean("filter", false) && prefs.getBoolean("use_hosts", false);
        if (lan && use_hosts) {
            List<InetAddress> listLocal = new ArrayList<>();
            try {
                Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
                if (nis != null)
                    while (nis.hasMoreElements()) {
                        NetworkInterface ni = nis.nextElement();
                        if (ni != null && ni.isUp() && !ni.isLoopback()) {
                            List<InterfaceAddress> ias = ni.getInterfaceAddresses();
                            if (ias != null)
                                for (InterfaceAddress ia : ias) {
                                    InetAddress hostAddress = ia.getAddress();
                                    BigInteger host = new BigInteger(1, hostAddress.getAddress());

                                    int prefix = ia.getNetworkPrefixLength();
                                    BigInteger mask = BigInteger.valueOf(-1).shiftLeft(hostAddress.getAddress().length * 8 - prefix);

                                    for (InetAddress dns : listDns)
                                        if (hostAddress.getAddress().length == dns.getAddress().length) {
                                            BigInteger ip = new BigInteger(1, dns.getAddress());

                                            if (host.and(mask).equals(ip.and(mask))) {
                                                Log.i(TAG, "Local DNS server host=" + hostAddress + "/" + prefix + " dns=" + dns);
                                                listLocal.add(dns);
                                            }
                                        }
                                }
                        }
                    }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            List<InetAddress> listDns4 = new ArrayList<>();
            List<InetAddress> listDns6 = new ArrayList<>();
            try {
                listDns4.add(InetAddress.getByName("8.8.8.8"));
                listDns4.add(InetAddress.getByName("8.8.4.4"));
                if (ip6) {
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8888"));
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8844"));
                }

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            for (InetAddress dns : listLocal) {
                listDns.remove(dns);
                if (dns instanceof Inet4Address) {
                    if (listDns4.size() > 0) {
                        listDns.add(listDns4.get(0));
                        listDns4.remove(0);
                    }
                } else {
                    if (listDns6.size() > 0) {
                        listDns.add(listDns6.get(0));
                        listDns6.remove(0);
                    }
                }
            }
        }

        return listDns;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private ParcelFileDescriptor startVPN(Builder builder) throws SecurityException {
        try {
            return builder.establish();
        } catch (SecurityException ex) {
            throw ex;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return null;
        }
    }

    private Builder getBuilder(List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean ip6 = prefs.getBoolean("ip6", false);
        boolean filter = prefs.getBoolean("filter", false);
        boolean system = prefs.getBoolean("manage_system", false);

        boolean block_hosts = prefs.getBoolean("block_hosts", false);
        // Build VPN service
        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));

        // VPN address
        String vpn4 = prefs.getString("vpn4", "10.1.10.1");
        Log.i(TAG, "vpn4=" + vpn4);
        builder.addAddress(vpn4, 32);
        if (ip6) {
            String vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1");
            Log.i(TAG, "vpn6=" + vpn6);
            builder.addAddress(vpn6, 128);
        }


        // DNS address
        if (block_hosts)
            for (InetAddress dns : getDns(ServiceSinkhole.this)) {
                if (ip6 || dns instanceof Inet4Address) {
                    Log.i(TAG, "dns=" + dns);
                    builder.addDnsServer(dns);
                }
            }

        // Subnet routing
        if (true) {
            // Exclude IP ranges
            List<IPUtil.CIDR> listExclude = new ArrayList<>();
            listExclude.add(new IPUtil.CIDR("127.0.0.0", 8)); // localhost

            listExclude.add(new IPUtil.CIDR("52.211.195.54", 32)); // isthatfreeproxysafe.com

            // Broadcast
            listExclude.add(new IPUtil.CIDR("224.0.0.0", 3));

            Collections.sort(listExclude);

            try {
                InetAddress start = InetAddress.getByName("0.0.0.0");
                for (IPUtil.CIDR exclude : listExclude) {
                    Log.i(TAG, "Exclude " + exclude.getStart().getHostAddress() + "..." + exclude.getEnd().getHostAddress());
                    for (IPUtil.CIDR include : IPUtil.toCIDR(start, IPUtil.minus1(exclude.getStart())))
                        try {
                            builder.addRoute(include.address, include.prefix);
                        } catch (Throwable ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                    start = IPUtil.plus1(exclude.getEnd());
                }
                for (IPUtil.CIDR include : IPUtil.toCIDR("224.0.0.0", "255.255.255.255"))
                    try {
                        builder.addRoute(include.address, include.prefix);
                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            } catch (UnknownHostException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        } else
            builder.addRoute("0.0.0.0", 0);

        Log.i(TAG, "IPv6=" + ip6);
        if (ip6)
            builder.addRoute("0:0:0:0:0:0:0:0", 0);

        // MTU
        int mtu = jni_get_mtu();
        Log.i(TAG, "MTU=" + mtu);
        builder.setMtu(mtu);

        // Add list of allowed applications
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            if (last_connected && !filter)
                for (Rule rule : listAllowed)
                    try {
                        builder.addDisallowedApplication(rule.info.packageName);
                    } catch (PackageManager.NameNotFoundException ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            else if (filter)
                for (Rule rule : listRule)
                    if (!rule.apply || (!system && rule.system))
                        try {
                            Log.i(TAG, "Not routing " + rule.info.packageName);
                            builder.addDisallowedApplication(rule.info.packageName);
                        } catch (PackageManager.NameNotFoundException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        return builder;
    }

    private void startNative(ParcelFileDescriptor vpn, List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean log = prefs.getBoolean("log", false);
        boolean log_app = prefs.getBoolean("log_app", true);
        boolean filter = prefs.getBoolean("filter", true);

        Log.i(TAG, "Start native log=" + log + "/" + log_app + " filter=" + filter);

        // Prepare rules
        if (filter) {
            prepareHostsBlocked();
            prepareUidAllowed(listAllowed, listRule);
        } else {
            lock.writeLock().lock();
            mapUidAllowed.clear();
            mapHostsBlocked.clear();
            mapUidKnown.clear();
            lock.writeLock().unlock();
        }

        if (log || log_app || filter) {
            int prio = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.ERROR)));
            if(BuildConfig.DEBUG) {
                prio = Log.DEBUG;
            }
            int rcode = Integer.parseInt(prefs.getString("rcode", "3"));
            jni_socks5("", 0, "", "");
            jni_start(vpn.getFd(), false, rcode, prio);
        }
    }

    private void stopNative(ParcelFileDescriptor vpn, boolean clear) {
        Log.i(TAG, "Stop native clear=" + clear);
        try {
            jni_stop(vpn.getFd(), clear);
        } catch (Throwable ex) {
            // File descriptor might be closed
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            jni_stop(-1, clear);
        }
    }

    private void unprepare() {
        lock.writeLock().lock();
        mapUidAllowed.clear();
        mapHostsBlocked.clear();
        mapUidKnown.clear();
        lock.writeLock().unlock();
    }

    private void prepareUidAllowed(List<Rule> listAllowed, List<Rule> listRule) {
        lock.writeLock().lock();

        mapUidAllowed.clear();
        for (Rule rule : listAllowed)
            mapUidAllowed.put(rule.info.applicationInfo.uid, true);

        mapUidKnown.clear();
        for (Rule rule : listRule)
            mapUidKnown.put(rule.info.applicationInfo.uid, rule.info.applicationInfo.uid);

        lock.writeLock().unlock();
    }

    private void prepareHostsBlocked() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean use_hosts = prefs.getBoolean("block_hosts", false);
        if(!use_hosts) {
            Log.i(TAG, "prepare hosts blocked, not using ads block");
            lock.writeLock().lock();
            mapHostsBlocked.clear();
            lock.writeLock().unlock();
            return;
        }
        File hosts = new File(getFilesDir(), "hosts.txt");
        if (!hosts.exists() || !hosts.canRead()) {
            Log.i(TAG, "Hosts file use=" + hosts + " exists=" + hosts.exists());
            lock.writeLock().lock();
            mapHostsBlocked.clear();
            lock.writeLock().unlock();
            return;
        }

        boolean changed = (hosts.lastModified() != last_hosts_modified);
        if (!changed && mapHostsBlocked.size() > 0) {
            Log.i(TAG, "Hosts file unchanged");
            return;
        }
        last_hosts_modified = hosts.lastModified();

        lock.writeLock().lock();

        mapHostsBlocked.clear();

        int count = 0;
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(hosts));
            String line;
            while ((line = br.readLine()) != null) {
                int hash = line.indexOf('#');
                if (hash >= 0)
                    line = line.substring(0, hash);
                line = line.trim();
                if (line.length() > 0) {
                    String[] words = line.split("\\s+");
                    if (words.length == 2) {
                        count++;
                        mapHostsBlocked.put(words[1], true);
                    } else
                        Log.i(TAG, "Invalid hosts file line: " + line);
                }
            }
            mapHostsBlocked.put("test.netguard.me", true);
            Log.i(TAG, count + " hosts read");
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            if (br != null)
                try {
                    br.close();
                } catch (IOException exex) {
                    Log.e(TAG, exex.toString() + "\n" + Log.getStackTraceString(exex));
                }
        }

        lock.writeLock().unlock();
    }

    private List<Rule> getAllowedRules(List<Rule> listRule) {
        return listRule;
    }

    private void stopVPN(ParcelFileDescriptor pfd) {
        Log.i(TAG, "Stopping");
        try {
            pfd.close();
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    // Called from native code
    private void nativeExit(String reason) {
        Log.w(TAG, "Native exit reason=" + reason);
        if (reason != null) {

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", false).apply();
        }
    }

    // Called from native code
    private void nativeError(int error, String message) {
        Log.w(TAG, "Native error " + error + ": " + message);
        //showErrorNotification(message);
    }

    // Called from native code
    private void logPacket(Packet packet) {
        Message msg = logHandler.obtainMessage();
        msg.obj = packet;
        msg.what = MSG_PACKET;
        logHandler.sendMessage(msg);
    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {
        if (DatabaseHelper.getInstance(ServiceSinkhole.this).insertDns(rr)) {
            Log.i(TAG, "New IP " + rr);
        }
    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        lock.readLock().lock();
        boolean blocked = (mapHostsBlocked.containsKey(name) && mapHostsBlocked.get(name));
        lock.readLock().unlock();
        return blocked;

    }

    private boolean isSupported(int protocol) {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 59 /* ICMPv6 */ ||
                protocol == 6 /* TCP */ ||
                protocol == 17 /* UDP */);
    }

    // Called from native code
    private Allowed getCurrentHttpProxy() {
        if(httpProxyList != null && !httpProxyList.isEmpty()) {
            return httpProxyList.get(httpProxyIdx).toAllowed();
        }
        return null;
    }

    // Called from native code
    private Allowed getCurrentHttpsProxy() {
        if(httpsProxyList != null && !httpsProxyList.isEmpty()) {
            return httpsProxyList.get(httpsProxyIdx).toAllowed();
        }
        return null;
    }

    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {

        if(jni_is_http_port(packet.dport)) {
            Log.i(TAG, "OAK : http connection redirecting to http proxy: port "+packet.dport);
            if(httpProxyList != null && !httpProxyList.isEmpty()) {
                Allowed proxy = httpProxyList.get(httpProxyIdx).toAllowed();
                Log.i(TAG, "OAK: use proxy: "+proxy.raddr+":"+proxy.rport);
                httpProxyIdx = (httpProxyIdx+1) % httpProxyList.size();
                return proxy;
            } else {
                Log.e(TAG, "No available http proxy...."+packet.daddr+":"+packet.dport);
            }
        } else if(jni_is_https_port(packet.dport)) {
            Log.i(TAG, "OAK : https connection redirecting to http proxy: port "+packet.dport);
            if(httpsProxyList != null && !httpsProxyList.isEmpty()) {
                Allowed proxy = httpsProxyList.get(httpsProxyIdx).toAllowed();
                Log.i(TAG, "OAK: use proxy: "+proxy.raddr+":"+proxy.rport);
                httpsProxyIdx = (httpsProxyIdx+1) % httpsProxyList.size();
                return proxy;
            } else if(httpProxyList != null && !httpProxyList.isEmpty()) {
                Allowed proxy = httpProxyList.get(httpProxyIdx).toAllowed();
                Log.w(TAG, "OAK: https proxy is not available. Use http proxy instead: "+proxy.raddr+":"+proxy.rport);
                httpProxyIdx = (httpProxyIdx+1) % httpProxyList.size();
                return proxy;
            } else {
                Log.e(TAG, "No available https and http available...."+packet.daddr+":"+packet.dport);
            }
        }
        return new Allowed();
    }

    // Called from native code
    private void accountUsage(Usage usage) {
        Message msg = logHandler.obtainMessage();
        msg.obj = usage;
        msg.what = MSG_USAGE;
        logHandler.sendMessage(msg);
    }

    // Called from native code
    private void proxyUsage(ProxyUsage usage) {
        Message msg = proxyUsageHandler.obtainMessage();
        msg.obj = usage;
        msg.what = MSG_PROXY_USAGE;
        proxyUsageHandler.sendMessage(msg);
    }

    private BroadcastReceiver proxyListReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);

            ArrayList<ProxyServerInfo> response = intent.getParcelableArrayListExtra("ProxyList");
            if(response != null) {
                httpProxyList = new ArrayList<>();
                httpsProxyList = new ArrayList<>();
                for(ProxyServerInfo psi : response) {
                    if(psi.httpsProxy) httpsProxyList.add(psi);
                    else httpProxyList.add(psi);
                }
                if(!httpProxyList.isEmpty()) jni_reset_proxy_perf(httpProxyList.get(0).addr, httpProxyList.get(0).port, 1);
                if(!httpsProxyList.isEmpty()) jni_reset_proxy_perf(httpsProxyList.get(0).addr, httpsProxyList.get(0).port, 0);
                else if(!httpProxyList.isEmpty()) jni_reset_proxy_perf(httpProxyList.get(0).addr, httpProxyList.get(0).port, 0);
            }
            Log.d(TAG, "HTTP Proxy: "+ Arrays.toString(httpProxyList.toArray())
            + ", HTTPS Proxy: "+Arrays.toString(httpsProxyList.toArray()));

        }
    };

    private BroadcastReceiver userReceiver = new BroadcastReceiver() {
        @Override
        @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR1)
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            user_foreground = Intent.ACTION_USER_FOREGROUND.equals(intent.getAction());
            Log.i(TAG, "User foreground=" + user_foreground + " user=" + (Process.myUid() / 100000));

            if (user_foreground) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("enabled", false)) {
                    // Allow service of background user to stop
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException ignored) {
                    }

                    start("foreground", ServiceSinkhole.this);
                }
            } else
                stop("background", ServiceSinkhole.this);
        }
    };

    private BroadcastReceiver idleStateReceiver = new BroadcastReceiver() {
        @Override
        @TargetApi(Build.VERSION_CODES.M)
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            Log.i(TAG, "device idle=" + pm.isDeviceIdleMode());

            // Reload rules when coming from idle mode
            if (!pm.isDeviceIdleMode())
                reload("idle state changed", ServiceSinkhole.this);
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Filter VPN connectivity changes
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                int networkType = intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY);
                if (networkType == ConnectivityManager.TYPE_VPN)
                    return;
            }

            // Reload rules
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);
            reload("connectivity changed", ServiceSinkhole.this);
        }
    };

    @Override
    public void onCreate() {
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this));

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Native init
        jni_init();
        boolean pcap = prefs.getBoolean("pcap", false);
        setPcap(pcap, this);

        prefs.registerOnSharedPreferenceChangeListener(this);

        Util.setTheme(this);
        super.onCreate();

        HandlerThread commandThread = new HandlerThread(getString(R.string.app_name) + " command", Process.THREAD_PRIORITY_FOREGROUND);
        HandlerThread logThread = new HandlerThread(getString(R.string.app_name) + " log", Process.THREAD_PRIORITY_BACKGROUND);
        HandlerThread statsThread = new HandlerThread(getString(R.string.app_name) + " stats", Process.THREAD_PRIORITY_BACKGROUND);
        HandlerThread proxyUsageThread = new HandlerThread(getString(R.string.app_name) + " proxy_usage", Process.THREAD_PRIORITY_BACKGROUND);
        commandThread.start();
        logThread.start();
        statsThread.start();
        proxyUsageThread.start();

        commandLooper = commandThread.getLooper();
        logLooper = logThread.getLooper();
        statsLooper = statsThread.getLooper();
        proxyUsageLooper = proxyUsageThread.getLooper();

        commandHandler = new CommandHandler(commandLooper);
        logHandler = new LogHandler(logLooper);
        proxyUsageHandler = new ProxyUsageHandler(proxyUsageLooper);

        // ------ OAK -------
        IntentFilter ifProxyList = new IntentFilter();
        ifProxyList.addAction(ActivityMain.ACTION_PROXY_LIST_CHANGED);
        registerReceiver(proxyListReceiver, ifProxyList);
        registeredProxyList = true;
        // ------------------

        // Listen for user switches
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            IntentFilter ifUser = new IntentFilter();
            ifUser.addAction(Intent.ACTION_USER_BACKGROUND);
            ifUser.addAction(Intent.ACTION_USER_FOREGROUND);
            registerReceiver(userReceiver, ifUser);
            registeredUser = true;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Listen for idle mode state changes
            IntentFilter ifIdle = new IntentFilter();
            ifIdle.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
            registerReceiver(idleStateReceiver, ifIdle);
            registeredIdleState = true;
        }

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);
        registeredConnectivityChanged = true;

        // Setup house holding
        Intent alarmIntent = new Intent(this, ServiceSinkhole.class);
        alarmIntent.setAction(ACTION_HOUSE_HOLDING);
        PendingIntent pi = PendingIntent.getService(this, 0, alarmIntent, PendingIntent.FLAG_UPDATE_CURRENT);

        AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
        am.setInexactRepeating(AlarmManager.RTC, SystemClock.elapsedRealtime() + 60 * 1000, AlarmManager.INTERVAL_HALF_DAY, pi);
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        if ("theme".equals(name)) {
            Log.i(TAG, "Theme changed");
            Util.setTheme(this);
            if (state != State.none) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
            }
            Log.d(TAG, "Start foreground state=" + state.toString());
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        // Check for set command
        if (intent != null && intent.hasExtra(EXTRA_COMMAND) &&
                intent.getSerializableExtra(EXTRA_COMMAND) == Command.set) {
            set(intent);
            return START_STICKY;
        }

        // Get state
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean enabled = prefs.getBoolean("enabled", false);

        // Handle service restart
        if (intent == null) {
            Log.i(TAG, "Restart");

            // Recreate intent
            intent = new Intent(this, ServiceSinkhole.class);
            intent.putExtra(EXTRA_COMMAND, enabled ? Command.start : Command.stop);
        }

        if (ACTION_HOUSE_HOLDING.equals(intent.getAction()))
            intent.putExtra(EXTRA_COMMAND, Command.householding);
        if (ACTION_WATCHDOG.equals(intent.getAction()))
            intent.putExtra(EXTRA_COMMAND, Command.watchdog);

        Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
        if (cmd == null)
            intent.putExtra(EXTRA_COMMAND, enabled ? Command.start : Command.stop);
        String reason = intent.getStringExtra(EXTRA_REASON);
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " reason=" + reason +
                " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

        commandHandler.queue(intent);
        return START_STICKY;
    }

    private void set(Intent intent) {
        // Get arguments
        int uid = intent.getIntExtra(EXTRA_UID, 0);
        String network = intent.getStringExtra(EXTRA_NETWORK);
        String pkg = intent.getStringExtra(EXTRA_PACKAGE);
        boolean blocked = intent.getBooleanExtra(EXTRA_BLOCKED, false);
        Log.i(TAG, "Set " + pkg + " " + network + "=" + blocked);

        // Get defaults
        SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean default_wifi = settings.getBoolean("whitelist_wifi", true);
        boolean default_other = settings.getBoolean("whitelist_other", true);

        // Update setting
        SharedPreferences prefs = getSharedPreferences(network, Context.MODE_PRIVATE);
        if (blocked == ("wifi".equals(network) ? default_wifi : default_other))
            prefs.edit().remove(pkg).apply();
        else
            prefs.edit().putBoolean(pkg, blocked).apply();

        // Apply rules
        ServiceSinkhole.reload("notification", ServiceSinkhole.this);

        // Update notification
        //notifyNewApplication(uid);

        // Update UI
        Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
        LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");

        // Disable firewall (will result in stop command)
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();

        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        commandLooper.quit();
        logLooper.quit();
        statsLooper.quit();
        proxyUsageLooper.quit();
        // ---- OAK
        if(registeredProxyList){
            unregisterReceiver(proxyListReceiver);
            registeredProxyList = false;
        }
        // ---------
        if (registeredUser) {
            unregisterReceiver(userReceiver);
            registeredUser = false;
        }
        if (registeredIdleState) {
            unregisterReceiver(idleStateReceiver);
            registeredIdleState = false;
        }
        if (registeredConnectivityChanged) {
            unregisterReceiver(connectivityChangedReceiver);
            registeredConnectivityChanged = false;
        }

        try {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
                unprepare();
            }
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        jni_done();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);

        super.onDestroy();
    }


    private class Builder extends VpnService.Builder {
        private int mtu;
        private List<String> listAddress = new ArrayList<>();
        private List<String> listRoute = new ArrayList<>();
        private List<InetAddress> listDns = new ArrayList<>();
        private List<String> listDisallowed = new ArrayList<>();

        private Builder() {
            super();
        }

        @Override
        public VpnService.Builder setMtu(int mtu) {
            this.mtu = mtu;
            super.setMtu(mtu);
            return this;
        }

        @Override
        public Builder addAddress(String address, int prefixLength) {
            listAddress.add(address + "/" + prefixLength);
            super.addAddress(address, prefixLength);
            return this;
        }

        @Override
        public Builder addRoute(String address, int prefixLength) {
            listRoute.add(address + "/" + prefixLength);
            super.addRoute(address, prefixLength);
            return this;
        }

        @Override
        public Builder addDnsServer(InetAddress address) {
            listDns.add(address);
            super.addDnsServer(address);
            return this;
        }

        @Override
        public Builder addDisallowedApplication(String packageName) throws PackageManager.NameNotFoundException {
            listDisallowed.add(packageName);
            super.addDisallowedApplication(packageName);
            return this;
        }

        @Override
        public boolean equals(Object obj) {
            Builder other = (Builder) obj;

            if (other == null)
                return false;

            if (this.mtu != other.mtu)
                return false;

            if (this.listAddress.size() != other.listAddress.size())
                return false;

            if (this.listRoute.size() != other.listRoute.size())
                return false;

            if (this.listDns.size() != other.listDns.size())
                return false;

            if (this.listDisallowed.size() != other.listDisallowed.size())
                return false;

            for (String address : this.listAddress)
                if (!other.listAddress.contains(address))
                    return false;

            for (String route : this.listRoute)
                if (!other.listRoute.contains(route))
                    return false;

            for (InetAddress dns : this.listDns)
                if (!other.listDns.contains(dns))
                    return false;

            for (String pkg : this.listDisallowed)
                if (!other.listDisallowed.contains(pkg))
                    return false;

            return true;
        }
    }

    public static void run(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.run);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void start(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void reload(String reason, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            Intent intent = new Intent(context, ServiceSinkhole.class);
            intent.putExtra(EXTRA_COMMAND, Command.reload);
            intent.putExtra(EXTRA_REASON, reason);
            context.startService(intent);
        }
    }

    public static void stop(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void reloadStats(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stats);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }
}
