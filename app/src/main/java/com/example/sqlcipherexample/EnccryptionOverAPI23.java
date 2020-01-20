package com.example.sqlcipherexample;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EnccryptionOverAPI23 {
    private Context Context;
    private static String ALIAS  = "AESalias";
    private static String AESTRANSFORMATION = "AES/GCM/NoPadding";
    private AppPreference appPreference = null;

    public EnccryptionOverAPI23(Context context) {
        this.Context = context;
        try {
            generateSecretKeyDemo();
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void generateSecretKeyDemo() {
        try {
            //Generate a key and store it in the KeyStore
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(ALIAS,
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

    public String decrypt() {
        byte[] decryptedBytes = null;
        try {
            appPreference = new AppPreference(Context);
            //Get the key
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null);
            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            String stringIV = appPreference.getIv();
            String stringEncryptedText = appPreference.getEncryption();
            byte[] iv = null;
            byte[] encryptionByte = null;

            if (stringIV != null) {
                String[] split = stringIV.substring(1, stringIV.length() - 1).split(", ");
                iv = new byte[split.length];
                for (int i = 0; i < split.length; i++) {
                    iv[i] = Byte.parseByte(split[i]);
                }
            }

            if (stringEncryptedText != null) {
                String[] split = stringEncryptedText.substring(1, stringEncryptedText.length() - 1).split(", ");
                encryptionByte = new byte[split.length];
                for (int i = 0; i < split.length; i++) {
                    encryptionByte[i] = Byte.parseByte(split[i]);
                }
            }

            //Extract info from map
            final byte[] encryptedBytes = encryptionByte;
            final byte[] ivBytes = iv;

            //Decrypt data
            final Cipher cipher = Cipher.getInstance(AESTRANSFORMATION);
            final GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptedBytes = cipher.doFinal(encryptedBytes);
            LogUtils.debug(Arrays.toString(decryptedBytes));
        } catch (Throwable e) {
            LogUtils.debug(e.toString());
        }

        return new String(decryptedBytes);
    }

    public void encrypt(final byte[] plainTextBytes) {

        try {
            appPreference = new AppPreference(Context);
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null);
            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            //Encrypt data
            final Cipher cipher = Cipher.getInstance(AESTRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] ivBytes = cipher.getIV();
            final byte[] encryptedBytes = cipher.doFinal(plainTextBytes);
            appPreference.setIv(Arrays.toString(ivBytes));
            appPreference.setEncryption( Arrays.toString(encryptedBytes));
            LogUtils.debug("AES ENCRYPTED IV: " + Arrays.toString(ivBytes));
            LogUtils.debug("AES ENCRYPTED TEXT: " +Arrays.toString(encryptedBytes));
        } catch (Throwable e) {
            LogUtils.debug(e.toString());
        }
    }
}

