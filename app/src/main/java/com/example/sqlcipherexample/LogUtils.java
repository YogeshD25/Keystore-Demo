package com.example.sqlcipherexample;

import android.util.Log;

public class LogUtils {
    public static final String  tag = "Keystore API Android";
    public static void debug( String message) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, message);
        }
    }
}