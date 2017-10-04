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

import android.Manifest;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;


import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class Util {

    private static final int NETWORK_TYPE_TD_SCDMA = 17;
    private static final int NETWORK_TYPE_IWLAN = 18;
    private static final String TAG = "NetGuard.Util";

    // Roam like at home
    private static final List<String> listEU = Arrays.asList(
            "AT", // Austria
            "BE", // Belgium
            "BG", // Bulgaria
            "HR", // Croatia
            "CY", // Cyprus
            "CZ", // Czech Republic
            "DK", // Denmark
            "EE", // Estonia
            "FI", // Finland
            "FR", // France
            "DE", // Germany
            "GR", // Greece
            "HU", // Hungary
            "IS", // Iceland
            "IE", // Ireland
            "IT", // Italy
            "LV", // Latvia
            "LI", // Liechtenstein
            "LT", // Lithuania
            "LU", // Luxembourg
            "MT", // Malta
            "NL", // Netherlands
            "NO", // Norway
            "PL", // Poland
            "PT", // Portugal
            "RO", // Romania
            "SK", // Slovakia
            "SI", // Slovenia
            "ES", // Spain
            "SE", // Sweden
            "GB" // United Kingdom
    );

    private static native String jni_getprop(String name);

    private static native boolean is_numeric_address(String ip);

    static {
        System.loadLibrary("netguard");
    }

    public static String getSelfVersionName(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionName;
        } catch (PackageManager.NameNotFoundException ex) {
            return ex.toString();
        }
    }

    public static int getSelfVersionCode(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionCode;
        } catch (PackageManager.NameNotFoundException ex) {
            return -1;
        }
    }

    public static String getNetworkGeneration(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.getType() == ConnectivityManager.TYPE_MOBILE ? getNetworkGeneration(ni.getSubtype()) : null);
    }

    public static boolean isNational(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            return (tm != null && tm.getSimCountryIso() != null && tm.getSimCountryIso().equals(tm.getNetworkCountryIso()));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean isEU(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            return (tm != null && isEU(tm.getSimCountryIso()) && isEU(tm.getNetworkCountryIso()));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean isEU(String country) {
        return (country != null && listEU.contains(country.toUpperCase()));
    }

    public static String getNetworkGeneration(int networkType) {
        switch (networkType) {
            case TelephonyManager.NETWORK_TYPE_1xRTT:
            case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_EDGE:
            case TelephonyManager.NETWORK_TYPE_GPRS:
            case TelephonyManager.NETWORK_TYPE_IDEN:
                return "2G";

            case TelephonyManager.NETWORK_TYPE_EHRPD:
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_EVDO_B:
            case TelephonyManager.NETWORK_TYPE_HSDPA:
            case TelephonyManager.NETWORK_TYPE_HSPA:
            case TelephonyManager.NETWORK_TYPE_HSPAP:
            case TelephonyManager.NETWORK_TYPE_HSUPA:
            case TelephonyManager.NETWORK_TYPE_UMTS:
            case NETWORK_TYPE_TD_SCDMA:
                return "3G";

            case TelephonyManager.NETWORK_TYPE_LTE:
            case NETWORK_TYPE_IWLAN:
                return "4G";

            default:
                return "?G";
        }
    }

    public static boolean hasPhoneStatePermission(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            return (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED);
        else
            return true;
    }

    public static List<String> getDefaultDNS(Context context) {
        String dns1 = null;
        String dns2 = null;
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.N_MR1) {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network an = cm.getActiveNetwork();
            if (an != null) {
                LinkProperties lp = cm.getLinkProperties(an);
                if (lp != null) {
                    List<InetAddress> dns = lp.getDnsServers();
                    if (dns != null) {
                        if (dns.size() > 0)
                            dns1 = dns.get(0).getHostAddress();
                        if (dns.size() > 1)
                            dns2 = dns.get(1).getHostAddress();
                        for (InetAddress d : dns)
                            Log.i(TAG, "DNS from LP: " + d.getHostAddress());
                    }
                }
            }
        } else {
            dns1 = jni_getprop("net.dns1");
            dns2 = jni_getprop("net.dns2");
        }

        List<String> listDns = new ArrayList<>();
        listDns.add(TextUtils.isEmpty(dns1) ? "8.8.8.8" : dns1);
        listDns.add(TextUtils.isEmpty(dns2) ? "8.8.4.4" : dns2);
        return listDns;
    }

    public static boolean isNumericAddress(String ip) {
        return is_numeric_address(ip);
    }

    public static boolean isInteractive(Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT_WATCH)
            return (pm != null && pm.isScreenOn());
        else
            return (pm != null && pm.isInteractive());
    }

    public static boolean isSystem(String packageName, Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(packageName, 0);
            return ((info.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0);
            /*
            PackageInfo pkg = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            PackageInfo sys = pm.getPackageInfo("android", PackageManager.GET_SIGNATURES);
            return (pkg != null && pkg.signatures != null && pkg.signatures.length > 0 &&
                    sys.signatures.length > 0 && sys.signatures[0].equals(pkg.signatures[0]));
            */
        } catch (PackageManager.NameNotFoundException ignore) {
            return false;
        }
    }

    public static boolean hasInternet(String packageName, Context context) {
        PackageManager pm = context.getPackageManager();
        return (pm.checkPermission("android.permission.INTERNET", packageName) == PackageManager.PERMISSION_GRANTED);
    }

    public static boolean isEnabled(PackageInfo info, Context context) {
        int setting;
        try {
            PackageManager pm = context.getPackageManager();
            setting = pm.getApplicationEnabledSetting(info.packageName);
        } catch (IllegalArgumentException ex) {
            setting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
            return info.applicationInfo.enabled;
        else
            return (setting == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
    }

    public static List<String> getApplicationNames(int uid, Context context) {
        List<String> listResult = new ArrayList<>();
        if (uid == 0)
            listResult.add(context.getString(R.string.title_root));
        else if (uid == 1013)
            listResult.add(context.getString(R.string.title_mediaserver));
        else if (uid == 9999)
            listResult.add(context.getString(R.string.title_nobody));
        else {
            PackageManager pm = context.getPackageManager();
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs == null)
                listResult.add(Integer.toString(uid));
            else
                for (String pkg : pkgs)
                    try {
                        ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                        listResult.add(pm.getApplicationLabel(info).toString());
                    } catch (PackageManager.NameNotFoundException ignored) {
                    }
            Collections.sort(listResult);
        }
        return listResult;
    }

    public static void setTheme(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean dark = prefs.getBoolean("dark_theme", false);
        String theme = prefs.getString("theme", "teal");
        if (theme.equals("teal"))
            context.setTheme(dark ? R.style.AppThemeTealDark : R.style.AppThemeTeal);
        else if (theme.equals("blue"))
            context.setTheme(dark ? R.style.AppThemeBlueDark : R.style.AppThemeBlue);
        else if (theme.equals("purple"))
            context.setTheme(dark ? R.style.AppThemePurpleDark : R.style.AppThemePurple);
        else if (theme.equals("amber"))
            context.setTheme(dark ? R.style.AppThemeAmberDark : R.style.AppThemeAmber);
        else if (theme.equals("orange"))
            context.setTheme(dark ? R.style.AppThemeOrangeDark : R.style.AppThemeOrange);
        else if (theme.equals("green"))
            context.setTheme(dark ? R.style.AppThemeGreenDark : R.style.AppThemeGreen);

        if (context instanceof Activity && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            TypedValue tv = new TypedValue();
            context.getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            ((Activity) context).setTaskDescription(new ActivityManager.TaskDescription(null, null, tv.data));
        }
    }

    public static int dips2pixels(int dips, Context context) {
        return Math.round(dips * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static void logExtras(Intent intent) {
        if (intent != null)
            logBundle(intent.getExtras());
    }

    public static void logBundle(Bundle data) {
        if (data != null) {
            Set<String> keys = data.keySet();
            StringBuilder stringBuilder = new StringBuilder();
            for (String key : keys) {
                Object value = data.get(key);
                stringBuilder.append(key)
                        .append("=")
                        .append(value)
                        .append(value == null ? "" : " (" + value.getClass().getSimpleName() + ")")
                        .append("\r\n");
            }
            Log.d(TAG, stringBuilder.toString());
        }
    }
}
