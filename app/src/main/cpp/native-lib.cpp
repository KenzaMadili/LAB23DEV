#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <android/log.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define LOG_TAG "ANTI_DEBUG"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

enum SecurityStatus {
    STATUS_OK = 0,
    STATUS_TRACE_DETECTED = 1,
    STATUS_MAPS_SUSPICIOUS = 2,
    STATUS_MULTIPLE_SIGNALS = 3
};

static bool drk_isBeingTraced() {
    long drk_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (drk_result == -1) {
        LOGE("Etat suspect : trace/debug detecte");
        return true;
    }
    LOGI("Aucun trace/debug detecte via ptrace");
    return false;
}

static bool drk_containsSuspiciousLibraryNames() {
    FILE* drk_maps = fopen("/proc/self/maps", "r");
    if (!drk_maps) {
        LOGW("Impossible d'ouvrir /proc/self/maps");
        return false;
    }

    char drk_line[512];
    while (fgets(drk_line, sizeof(drk_line), drk_maps)) {
        if (strstr(drk_line, "frida") ||
            strstr(drk_line, "xposed") ||
            strstr(drk_line, "libfrida") ||
            strstr(drk_line, "gdbserver") ||
            strstr(drk_line, "libgdb") ||
            strstr(drk_line, "magisk")) {
            LOGE("Signature suspecte trouvee dans maps : %s", drk_line);
            fclose(drk_maps);
            return true;
        }
    }
    fclose(drk_maps);
    return false;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_NativeSecurityManager_getSecurityStatus(
        JNIEnv* env,
        jobject /* this */) {

    bool drk_traced = drk_isBeingTraced();
    bool drk_suspiciousMaps = drk_containsSuspiciousLibraryNames();

    if (drk_traced && drk_suspiciousMaps) return STATUS_MULTIPLE_SIGNALS;
    if (drk_traced) return STATUS_TRACE_DETECTED;
    if (drk_suspiciousMaps) return STATUS_MAPS_SUSPICIOUS;

    return STATUS_OK;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_jnidemo_MainActivity_isDebugDetected(JNIEnv* env, jobject obj) {
    return drk_isBeingTraced() || drk_containsSuspiciousLibraryNames();
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_helloFromJNI(JNIEnv* env, jobject obj) {
    return env->NewStringUTF("Hello from C++ via JNI !");
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_MainActivity_factorial(JNIEnv* env, jobject obj, jint n) {
    if (n < 0) return -1;
    long long drk_fact = 1;
    for (int i = 1; i <= n; i++) drk_fact *= i;
    return static_cast<jint>(drk_fact);
}