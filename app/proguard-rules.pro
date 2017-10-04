# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /home/marcel/Android/Sdk/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

#Line numbers
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

#NetGuard
-keepnames class com.isthatfreeproxysafe.ciao.** { *; }

#JNI
-keepclasseswithmembernames class * {
    native <methods>;
}

#JNI callbacks
-keep class com.isthatfreeproxysafe.ciao.Allowed { *; }
-keep class com.isthatfreeproxysafe.ciao.Packet { *; }
-keep class com.isthatfreeproxysafe.ciao.ResourceRecord { *; }
-keep class com.isthatfreeproxysafe.ciao.Usage { *; }
-keep class com.isthatfreeproxysafe.ciao.ProxyUsage { *; }
-keep class com.isthatfreeproxysafe.ciao.ServiceSinkhole {
    void nativeExit(java.lang.String);
    void nativeError(int, java.lang.String);
    void logPacket(com.isthatfreeproxysafe.ciao.Packet);
    void dnsResolved(com.isthatfreeproxysafe.ciao.ResourceRecord);
    boolean isDomainBlocked(java.lang.String);
    com.isthatfreeproxysafe.ciao.Allowed isAddressAllowed(com.isthatfreeproxysafe.ciao.Packet);
    com.isthatfreeproxysafe.ciao.Allowed getCurrentHttpProxy();
    com.isthatfreeproxysafe.ciao.Allowed getCurrentHttpsProxy();
    void accountUsage(com.isthatfreeproxysafe.ciao.Usage);
    void proxyUsage(com.isthatfreeproxysafe.ciao.ProxyUsage);
}

#Support library
-keep class android.support.v7.widget.** { *; }
-dontwarn android.support.v4.**

#Picasso
#-dontwarn com.squareup.okhttp.**

#AdMob
#-dontwarn com.google.android.gms.internal.**
