package com.example.sqlcipherexample;

import android.content.Context;

import java.io.File;

public class Utils {
    public static File getInternalDirectoryPath(Context context) {
        return context.getFilesDir();
    }
}
