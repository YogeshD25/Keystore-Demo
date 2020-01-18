package com.example.sqlcipherexample;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyStore;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESEncryption {
    AESEncryption() {
        super();
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void testEncryption(Context context) {
        try {
            //Generate a key and store it in the KeyStore
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("MyKeyAliasAES",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    //.setUserAuthenticationRequired(true) //requires lock screen, invalidated if lock screen is disabled
                    //.setUserAuthenticationValidityDurationSeconds(120) //only available x seconds from password authentication. -1 requires finger print - every time
                    .setRandomizedEncryptionRequired(true) //different ciphertext for same plaintext on each call
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

            //Test
            final HashMap<String, byte[]> map = encrypt("My very sensitive string!".getBytes("UTF-8"));
            final byte[] decryptedBytes = decrypt(map);
            final String decryptedString = new String(decryptedBytes, "UTF-8");
            Log.e("MyApp", "The decrypted string is " + decryptedString);
            Toast.makeText(context, "decryptedString", Toast.LENGTH_SHORT).show();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private byte[] decrypt(final HashMap<String, byte[]> map) {
        byte[] decryptedBytes = null;
        try {
            //Get the key
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("MyKeyAliasAES", null);
            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            //Extract info from map
            final byte[] encryptedBytes = map.get("encrypted");
            final byte[] ivBytes = map.get("iv");

            //Decrypt data
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptedBytes = cipher.doFinal(encryptedBytes);
        } catch (Throwable e) {
            e.printStackTrace();
        }

        return decryptedBytes;
    }

    private HashMap<String, byte[]> encrypt(final byte[] decryptedBytes) {
        final HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        try {
            //Get the key
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("MyKeyAliasAES", null);
            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            //Encrypt data
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] ivBytes = cipher.getIV();
            final byte[] encryptedBytes = cipher.doFinal(decryptedBytes);
            map.put("iv", ivBytes);
            map.put("encrypted", encryptedBytes);
        } catch (Throwable e) {
            e.printStackTrace();
        }

        return map;
    }
}
