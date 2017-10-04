package com.isthatfreeproxysafe.ciao;

import android.content.Context;

import static com.isthatfreeproxysafe.ciao.ProxyWebAPI.concatQueries;
import static com.isthatfreeproxysafe.ciao.ProxyWebAPI.generateRegionQuery;
import static com.isthatfreeproxysafe.ciao.ProxyWebAPI.generateStrategyQuery;
import static com.isthatfreeproxysafe.ciao.ProxyWebAPI.getDeviceSpecificQuery;

/**
 * Created by b.ran on 15/09/17.
 */

public class ProxySetting {

    private int proxyType;
    private String region;
    private Context context;

    public ProxySetting(Context context) {
        this.proxyType = 6;
        this.region = null;
        this.context = context;
    }

    public ProxySetting(String proxyType, String region, Context context) {
        this.proxyType = ProxyWebAPI.getStrategyFromProxyType(context, proxyType);
        this.region = region;
        this.context = context;
    }

    public ProxySetting(ProxySetting other) {
        this.proxyType = other.proxyType;
        this.region = other.region;
        this.context = other.context;
    }

    public String toQueryString() {
        if(region == null || region.isEmpty()) return concatQueries(generateStrategyQuery(proxyType),getDeviceSpecificQuery(context));
        return concatQueries(generateRegionQuery(region), generateStrategyQuery(proxyType),getDeviceSpecificQuery(context));
    }

    public boolean sameConfig(ProxySetting other) {
        if(other == null) return false;
        if ((this.region == null) ? (other.region != null) : !this.region.equals(other.region)) {
            return false;
        }
        return this.proxyType == other.proxyType;
    }

    public String toConfigString() {
        return "region="+region+" : "+"strategy="+proxyType;
    }
}
