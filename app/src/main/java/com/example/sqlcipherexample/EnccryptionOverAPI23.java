package com.example.sqlcipherexample;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EnccryptionOverAPI23 {
    private Context context;
    private KeyStore keyStore;
    private static String alias = "AESalias";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private byte[] encryption;
    private byte[] iv;

    public EnccryptionOverAPI23(Context context) {
        this.context = context;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            generateSecretKey();
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
    }


    @TargetApi(Build.VERSION_CODES.M)
    private void generateSecretKey(final String alias) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final KeyGenerator keyGenerator;

        keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
        }
    }


    void encryptText(final String alias, final String textToEncrypt, Context context)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchPaddingException, InvalidKeyException, IOException,
            BadPaddingException,
            IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias));
        iv = cipher.getIV();
        encryption = cipher.doFinal(textToEncrypt.getBytes("UTF-8"));
    }

    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
            UnrecoverableEntryException, KeyStoreException {
        return ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();
    }

    String decryptData(final String alias, final byte[] encryptedData, final byte[] encryptionIv)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchPaddingException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), spec);

        return new String(cipher.doFinal(encryptedData), "UTF-8");
    }


    @TargetApi(Build.VERSION_CODES.M)
    public void generateSecretKey() {
        try {
            //Generate a key and store it in the KeyStore
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    //.setUserAuthenticationRequired(true) //requires lock screen, invalidated if lock screen is disabled
                    //.setUserAuthenticationValidityDurationSeconds(120) //only available x seconds from password authentication. -1 requires finger print - every time
                    .setRandomizedEncryptionRequired(true) //different ciphertext for same plaintext on each call
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

        } catch (Throwable e) {
            LogUtils.debug(e.toString());
        }
    }

    private byte[] decrypt(final HashMap<String, byte[]> map) {
        byte[] decryptedBytes = null;
        try {
            //Get the key
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);
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
            LogUtils.debug(e.toString());
        }

        return decryptedBytes;
    }

    private HashMap<String, byte[]> encrypt(final byte[] decryptedBytes) {
        final HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        try {
            //Get the key

            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);
            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            //Encrypt data
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] ivBytes = cipher.getIV();
            final byte[] encryptedBytes = cipher.doFinal(decryptedBytes);
            map.put("iv", ivBytes);
            map.put("encrypted", encryptedBytes);
        } catch (Throwable e) {
            LogUtils.debug(e.toString());
        }

        return map;
    }
}

