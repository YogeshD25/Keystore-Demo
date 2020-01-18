package com.example.sqlcipherexample;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashMap;

public class AppPreference {

    private Context mContext;
    private SharedPreferences preferences;
    private String PREFERENCE_NAME = "Encrypto";

    public AppPreference(Context context) {
        mContext = context;
        preferences = mContext.getSharedPreferences(PREFERENCE_NAME,
                Context.MODE_PRIVATE);
    }

    public String getMobileNumber() {
        return preferences.getString(Keys.KEY_MOBILE_NUMBER, null);
    }

    public void setMobileNumber(String host) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(Keys.KEY_MOBILE_NUMBER, host);
        editor.apply();
    }
    public String getEncryption() {
        return preferences.getString(Keys.KEY_ENCRYTION, null);
    }

    public void setEncryption(String host) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(Keys.KEY_ENCRYTION, host);
        editor.apply();
    }
    public String getIv() {
        return preferences.getString(Keys.IV_BYTES, null);
    }

    public void setIv(String host) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(Keys.IV_BYTES, host);
        editor.apply();
    }

    public void removeSecretData(){
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(Keys.KEY_MOBILE_NUMBER);
        editor.remove(Keys.KEY_ENCRYTION);
        editor.remove(Keys.IV_BYTES);
        editor.apply();
    }

    private interface Keys {
        String KEY_MOBILE_NUMBER = "_mobileNumber";
        String KEY_ENCRYTION = "_encryption";
        String IV_BYTES = "_ivBytes";


    }
}
