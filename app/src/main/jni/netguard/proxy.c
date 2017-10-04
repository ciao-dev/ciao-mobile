//
// Created by b.ran on 12/09/17.
//

#include "netguard.h"
extern jclass clsProxyUsage;
extern jclass clsAllowed;
extern jfieldID fidRaddr;
extern jfieldID fidRport;
extern jfieldID fidRedirect;
extern struct allowed allowed;

jmethodID midProxyUsage = NULL;
jmethodID midInitProxyUsage = NULL;
jfieldID fidProxyUsageStartTime = NULL;
jfieldID fidProxyUsageEndTime = NULL;
jfieldID fidProxyUsageLastRecvTime = NULL;
jfieldID fidProxyUsageProtocol = NULL;
jfieldID fidProxyUsageDAddr = NULL;
jfieldID fidProxyUsageDPort = NULL;
jfieldID fidProxyUsageUid = NULL;
jfieldID fidProxyUsageSent = NULL;
jfieldID fidProxyUsageReceived = NULL;
jfieldID fidProxyUsageHttpProxyAddr = NULL;
jfieldID fidProxyUsageHttpProxyPort = NULL;
jfieldID fidProxyUsageHttpsProxyAddr = NULL;
jfieldID fidProxyUsageHttpsProxyPort = NULL;

void proxy_usage(const struct arguments *args, jint protocol,
                 const char *daddr, jint dport, jint uid, jlong sent, jlong received, jlong start_time,
                 jlong last_recv_time, struct allowed* http_proxy, struct allowed* https_proxy) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);

    const char *signature = "(Lcom/isthatfreeproxysafe/ciao/ProxyUsage;)V";
    if (midProxyUsage == NULL)
        midProxyUsage = jniGetMethodID(args->env, clsService, "proxyUsage", signature);

    const char *usage = "com/isthatfreeproxysafe/ciao/ProxyUsage";
    if (midInitProxyUsage == NULL)
        midInitProxyUsage = jniGetMethodID(args->env, clsProxyUsage, "<init>", "()V");

    jobject jpusage = jniNewObject(args->env, clsProxyUsage, midInitProxyUsage, usage);

    if (fidProxyUsageStartTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidProxyUsageStartTime = jniGetFieldID(args->env, clsProxyUsage, "StartTime", "J");
        fidProxyUsageEndTime = jniGetFieldID(args->env, clsProxyUsage, "EndTime", "J");
        fidProxyUsageLastRecvTime = jniGetFieldID(args->env, clsProxyUsage, "LastRecvTime", "J");
        fidProxyUsageProtocol = jniGetFieldID(args->env, clsProxyUsage, "AppLayerProt", "I");
        fidProxyUsageDAddr = jniGetFieldID(args->env, clsProxyUsage, "DAddr", string);
        fidProxyUsageDPort = jniGetFieldID(args->env, clsProxyUsage, "DPort", "I");
        fidProxyUsageUid = jniGetFieldID(args->env, clsProxyUsage, "Uid", "I");
        fidProxyUsageSent = jniGetFieldID(args->env, clsProxyUsage, "Sent", "J");
        fidProxyUsageReceived = jniGetFieldID(args->env, clsProxyUsage, "Received", "J");
        fidProxyUsageHttpProxyAddr = jniGetFieldID(args->env, clsProxyUsage, "HttpProxyAddr", string);
        fidProxyUsageHttpProxyPort = jniGetFieldID(args->env, clsProxyUsage, "HttpProxyPort", "I");
        fidProxyUsageHttpsProxyAddr = jniGetFieldID(args->env, clsProxyUsage, "HttpsProxyAddr", string);
        fidProxyUsageHttpsProxyPort = jniGetFieldID(args->env, clsProxyUsage, "HttpsProxyPort", "I");
    }

    jlong jtime = get_epoch_time();
    jstring jdaddr = (*args->env)->NewStringUTF(args->env, daddr);

    (*args->env)->SetLongField(args->env, jpusage, fidProxyUsageStartTime, start_time);
    (*args->env)->SetLongField(args->env, jpusage, fidProxyUsageEndTime, jtime);
    (*args->env)->SetLongField(args->env, jpusage, fidProxyUsageLastRecvTime, last_recv_time);
    (*args->env)->SetIntField(args->env, jpusage, fidProxyUsageProtocol, protocol);
    (*args->env)->SetObjectField(args->env, jpusage, fidProxyUsageDAddr, jdaddr);
    (*args->env)->SetIntField(args->env, jpusage, fidProxyUsageDPort, dport);
    (*args->env)->SetIntField(args->env, jpusage, fidProxyUsageUid, uid);
    (*args->env)->SetLongField(args->env, jpusage, fidProxyUsageSent, sent);
    (*args->env)->SetLongField(args->env, jpusage, fidProxyUsageReceived, received);

    jstring jhttpaddr;
    if(!http_proxy->masked) {
        jhttpaddr = (*args->env)->NewStringUTF(args->env, http_proxy->raddr);
        (*args->env)->SetObjectField(args->env, jpusage, fidProxyUsageHttpProxyAddr, jhttpaddr);
        (*args->env)->SetIntField(args->env, jpusage, fidProxyUsageHttpProxyPort,
                                  http_proxy->rport);
    }
    jstring jhttpsaddr;
    if(!https_proxy->masked) {
        jhttpsaddr = (*args->env)->NewStringUTF(args->env, https_proxy->raddr);
        (*args->env)->SetObjectField(args->env, jpusage, fidProxyUsageHttpsProxyAddr, jhttpsaddr);
        (*args->env)->SetIntField(args->env, jpusage, fidProxyUsageHttpsProxyPort, https_proxy->rport);
    }

    (*args->env)->CallVoidMethod(args->env, args->instance, midProxyUsage, jpusage);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jdaddr);
    (*args->env)->DeleteLocalRef(args->env, jpusage);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    if(!https_proxy->masked)( *args->env)->DeleteLocalRef(args->env, jhttpsaddr);
    if(!http_proxy->masked) (*args->env)->DeleteLocalRef(args->env, jhttpaddr);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_proxy_packet %f", mselapsed);
#endif
}

static jmethodID midGetCurrenHttpProxy = NULL;
struct allowed *get_current_http_proxy(const struct arguments *args) {
    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    const char *signature = "()Lcom/isthatfreeproxysafe/ciao/Allowed;";
    if (midGetCurrenHttpProxy == NULL)
        midGetCurrenHttpProxy = jniGetMethodID(args->env, clsService, "getCurrentHttpProxy", signature);

    jobject jproxy = (*args->env)->CallObjectMethod(
            args->env, args->instance, midGetCurrenHttpProxy);
    if (jproxy != NULL) {
        if (fidRaddr == NULL) {
            const char *string = "Ljava/lang/String;";
            fidRaddr = jniGetFieldID(args->env, clsAllowed, "raddr", string);
            fidRport = jniGetFieldID(args->env, clsAllowed, "rport", "I");
            fidRedirect = jniGetFieldID(args->env, clsAllowed, "redirect", "Z");
        }
        jstring jraddr = (*args->env)->GetObjectField(args->env, jproxy, fidRaddr);
        if (jraddr == NULL) {
            *allowed.raddr = 0;
        }
        else {
            const char *raddr = (*args->env)->GetStringUTFChars(args->env, jraddr, NULL);
            strcpy(allowed.raddr, raddr);
            (*args->env)->ReleaseStringUTFChars(args->env, jraddr, raddr);
        }
        allowed.rport = (uint16_t) (*args->env)->GetIntField(args->env, jproxy, fidRport);
        allowed.redirect = (uint8_t) (*args->env)->GetBooleanField(args->env, jproxy, fidRedirect);

        (*args->env)->DeleteLocalRef(args->env, jraddr);
    }
    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jproxy);

    return (jproxy == NULL ? NULL : &allowed);
}

static jmethodID midGetCurrenHttpsProxy = NULL;
struct allowed *get_current_https_proxy(const struct arguments *args) {
    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    const char *signature = "()Lcom/isthatfreeproxysafe/ciao/Allowed;";
    if (midGetCurrenHttpsProxy == NULL)
        midGetCurrenHttpsProxy = jniGetMethodID(args->env, clsService, "getCurrentHttpsProxy", signature);

    jobject jproxy = (*args->env)->CallObjectMethod(
            args->env, args->instance, midGetCurrenHttpsProxy);
    if (jproxy != NULL) {
        if (fidRaddr == NULL) {
            const char *string = "Ljava/lang/String;";
            fidRaddr = jniGetFieldID(args->env, clsAllowed, "raddr", string);
            fidRport = jniGetFieldID(args->env, clsAllowed, "rport", "I");
            fidRedirect = jniGetFieldID(args->env, clsAllowed, "redirect", "Z");
        }
        jstring jraddr = (*args->env)->GetObjectField(args->env, jproxy, fidRaddr);
        if (jraddr == NULL)
            *allowed.raddr = 0;
        else {
            const char *raddr = (*args->env)->GetStringUTFChars(args->env, jraddr, NULL);
            strcpy(allowed.raddr, raddr);
            (*args->env)->ReleaseStringUTFChars(args->env, jraddr, raddr);
        }
        allowed.rport = (uint16_t) (*args->env)->GetIntField(args->env, jproxy, fidRport);
        allowed.redirect = (uint8_t) (*args->env)->GetBooleanField(args->env, jproxy, fidRedirect);

        (*args->env)->DeleteLocalRef(args->env, jraddr);
    }
    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jproxy);

    return (jproxy == NULL ? NULL : &allowed);

}