package com.isthatfreeproxysafe.ciao;

import android.util.Log;

import java.util.Random;

/**
 * Created by b.ran on 4/09/17.
 */

public class ProxyUtil {
    final private static String TAG = ProxyUtil.class.getSimpleName();

    final public static int MAX_PROXY_USAGE_SIZE = 10;
    private static long sessionId = -1;

    public static void generateSessionId() {
        sessionId = new Random(System.currentTimeMillis()).nextLong();
        Log.d(TAG, "Current session id: "+sessionId);
    }

    public static long getSessionId() {
        return sessionId;
    }

    private static long enableId = -1;
    public static void generateEnableId() {
        enableId = new Random(System.currentTimeMillis()).nextLong();
        Log.d(TAG, "Current enabled id: "+enableId);
    }
    public static long getEnableId() { return enableId; }
}
