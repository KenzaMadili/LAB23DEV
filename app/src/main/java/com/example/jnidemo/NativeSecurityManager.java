package com.example.jnidemo;

public class NativeSecurityManager {
    // Codes d'état
    public static final int STATUS_OK = 0;
    public static final int STATUS_TRACE_DETECTED = 1;
    public static final int STATUS_MAPS_SUSPICIOUS = 2;
    public static final int STATUS_MULTIPLE_SIGNALS = 3;

    static {
        System.loadLibrary("native-lib");
    }


    public native int getSecurityStatus();
}
