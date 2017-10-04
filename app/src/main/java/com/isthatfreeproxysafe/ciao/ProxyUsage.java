package com.isthatfreeproxysafe.ciao;

import android.content.Context;

import org.json.simple.JSONObject;

/**
 * Created by b.ran on 12/09/17.
 */

public class ProxyUsage {
    public long StartTime;
    public long EndTime;
    public long LastRecvTime;
    public int Version;
    public String DAddr;
    public int DPort;
    public int Uid;
    public long Sent;
    public long Received;
    public int AppLayerProt;
    public String HttpProxyAddr = null;
    public int HttpProxyPort;
    public String HttpsProxyAddr = null;
    public int HttpsProxyPort;

    public JSONObject toJsonObject(Context context) {
        JSONObject json = new JSONObject();
        json.put("StartTime", StartTime);
        //json.put("Destination", DAddr);
        json.put("LastRecvTime", LastRecvTime);
        json.put("EndTime", EndTime);
        json.put("Protocol", AppLayerProt == 1 ? "HTTP" : AppLayerProt == 2 ? "HTTPS" : "Other");
        json.put("PackageName", context.getPackageManager().getNameForUid(Uid));
        json.put("AmountSent", Sent);
        json.put("AmountRecv", Received);
        json.put("SessionId", ProxyUtil.getSessionId());
        json.put("EnabledId", ProxyUtil.getEnableId());

        json.put("MainProxy", HttpProxyAddr+":"+HttpProxyPort);
        json.put("MainHttpsProxy", HttpsProxyAddr+":"+HttpsProxyPort);
        /*DatabaseHelper dh = DatabaseHelper.getInstance(context);
        String dname = dh.getQName(Uid, DAddr);
        json.put("DName", dname);*/
        return json;

    }

    public String toJson(Context context) {
        return this.toJsonObject(context).toString();
    }
}

