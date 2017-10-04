//
// Created by b.ran on 26/07/17.
//

#include "netguard.h"

#define HOST_HTTP_TEXT "Host: "

void gethttphostname(const char *buffer, int *start, int *len) {
    if(buffer == NULL) return;
    char *hostidx = strstr(buffer, HOST_HTTP_TEXT);
    if(hostidx == NULL) {
        return;
    }
    char *hostidxend = strchr(hostidx, '\n');
    if(hostidxend == NULL) {
        log_android(ANDROID_LOG_DEBUG, "OAK: something is wrong here..");
        return;
    }
    *start = hostidx+strlen(HOST_HTTP_TEXT)-buffer;
    *len = hostidxend - 1 - (hostidx + strlen(HOST_HTTP_TEXT)); // 6 is for "Host: "
    log_android(ANDROID_LOG_DEBUG, "OAK: hostidx start at %.*s - len %d", *len, buffer+*start, *len);
}

