package com.isthatfreeproxysafe.ciao;

import android.content.Context;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created by b.ran on 8/09/17.
 */

public class ProxyWebAPI {
    final public static String WEB_API_DOMAINNAME = "isthatfreeproxysafe.com";
    final public static String WEB_API_HOSTNAME = "api.mobile." + WEB_API_DOMAINNAME;
    final public static String DEFAULT_QUERY_URL = "http://" + WEB_API_HOSTNAME + "/query.php";
    final public static String DEFAULT_COUNTRY_QUERY_URL = "https://" + WEB_API_HOSTNAME + "/query_country.php";
    final public static String HTTPS_QUERY_URL = "https://" + WEB_API_HOSTNAME + "/query.php";
    final public static String TEST_URL = "http://" + WEB_API_DOMAINNAME + "/test/hello.html";

    final public static String STATS_WEB_API_DOMAINNAME = "https://" + WEB_API_HOSTNAME; // "192.168.3.176"; //WEB_API_HOSTNAME
    final public static String STATS_WEB_API_PATH = "/report.php";

    public static String getSessionQuery() {
        return "session_id="+ProxyUtil.getSessionId();
    }

    public static String getEnableIdQuery() { return "enabled_id="+ProxyUtil.getEnableId(); }

    public static String getDeviceSpecificQuery(Context context) {
        return concatQueries(getSessionQuery(), getVersion(context), getEnableIdQuery());
    }

    public static String getDefaultQuery(Context context) {
        return concatQueries("strategy=6", getDeviceSpecificQuery(context));
    }

    public static String getVersion(Context context) {
        return "version="+Util.getSelfVersionName(context);
    }

    public static int getStrategyFromProxyType(Context context, String proxyType) {
        int strategy = 6;
        if(proxyType != null) {
            if (proxyType.contains(context.getText(R.string.proxy_type_anonymous))) strategy = 7;
            if (proxyType.contains(context.getText(R.string.proxy_type_elite))) strategy = 8;
            if (proxyType.contains(context.getText(R.string.proxy_type_transparent))) strategy = 9;
        }
        return strategy;

    }

    public static String generateStrategyQuery(int strategy) {
        return "strategy="+strategy;
    }

    public static String generateStrategyQuery(Context context, String proxyType) {
        return "strategy="+getStrategyFromProxyType(context, proxyType);
    }

    public static String concatQueries(String... qs){
        StringBuilder out = new StringBuilder();
        boolean started = false;
        for(String q : qs) {
            if(q.isEmpty()) continue;
            if(started) out = out.append("&");
            else started = true;
            out = out.append(q);
        }
        return out.toString();
    }

    public static String concatQueriesWithDeviceSpecificQuery(Context context, String... qs) {
        List<String> ar = new ArrayList<>(qs.length+1);
        Collections.addAll(ar, qs);
        ar.add(getDeviceSpecificQuery(context));
        return concatQueries(ar.toArray(new String[ar.size()]));
    }

    public static String generateRegionQuery(String cc) {
        return "region="+cc;
    }
}
