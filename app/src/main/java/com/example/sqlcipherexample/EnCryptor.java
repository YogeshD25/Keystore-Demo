package com.example.sqlcipherexample;

import android.app.AliasActivity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * ______        _____                  _
 * |  ____|      / ____|                | |
 * | |__   _ __ | |     _ __ _   _ _ __ | |_ ___  _ __
 * |  __| | '_ \| |    | '__| | | | '_ \| __/ _ \| '__|
 * | |____| | | | |____| |  | |_| | |_) | || (_) | |
 * |______|_| |_|\_____|_|   \__, | .__/ \__\___/|_|
 * __/ | |
 * |___/|_|
 */
class EnCryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String RSA_MODE =  "RSA/ECB/PKCS1Padding";
    private static final String AES_MODE = "AES/ECB/PKCS7Padding";
    private static final String ALIAS_NAME = "RSADEMO";

    private byte[] encryption;
    private byte[] iv;
    private KeyStore keyStore;


    private void initKeyStore() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
    }

    byte[] encryptText(final String alias, final String textToEncrypt)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
            InvalidAlgorithmParameterException, SignatureException, BadPaddingException,
            IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias));
        iv = cipher.getIV();
        return (encryption = cipher.doFinal(textToEncrypt.getBytes("UTF-8")));
    }


    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

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
        return keyGenerator.generateKey();
    }

//    //TODO For Previous Version than API 21
//
//    private void RSAKeyGenerator(final String alias, final Context context) {
//        String AndroidKeyStore = "AndroidKeyStore";
//        KeyStore keyStore = null;
//        try {
//            keyStore = KeyStore.getInstance(AndroidKeyStore);
//            keyStore.load(null);
//            if (!keyStore.containsAlias(alias)) {
//                Calendar start = Calendar.getInstance();
//                Calendar end = Calendar.getInstance();
//                end.add(Calendar.YEAR, 30);
//                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
//                        .setAlias(alias)
//                        .setSubject(new X500Principal("CN=" + alias))
//                        .setSerialNumber(BigInteger.TEN)
//                        .setStartDate(start.getTime())
//                        .setEndDate(end.getTime())
//                        .build();
//                KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, AndroidKeyStore);
//                kpg.initialize(spec);
//                kpg.generateKeyPair();
//
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    byte[] getEncryption() {
//        return encryption;
//    }
//
//    byte[] getIv() {
//        return iv;
//    }
//    private byte[] rsaEncrypt(byte[] secret ,Context context) throws Exception{
//        RSAKeyGenerator(ALIAS_NAME,context);
//        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS_NAME, null);
//        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
//        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());
//
//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
//        cipherOutputStream.write(secret);
//        cipherOutputStream.close();
//        return outputStream.toByteArray();
//    }
//    public  String genAESKeyBasedOnRSA(String ENCRYPTED_KEY, Context context){
//        if (ENCRYPTED_KEY == null) {
//            byte[] key = new byte[16];
//            SecureRandom secureRandom = new SecureRandom();
//            secureRandom.nextBytes(key);
//            byte[] encryptedKey = new byte[0];
//            try {
//                encryptedKey = rsaEncrypt(key,context);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//            ENCRYPTED_KEY = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
//        }
//        return  ENCRYPTED_KEY;
//    }
//    private Key getSecretKeyFromRSA(Context context) throws Exception{
//        String enryptedKeyB64 = genAESKeyBasedOnRSA("ABCD",context);
//        byte[] encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT);
//        byte[] key = rsaDecrypt(encryptedKey);
//        return new SecretKeySpec(key, "AES");
//    }
//
//    public String encrypt(Context context, byte[] input) throws Exception {
//        Cipher c = Cipher.getInstance(AES_MODE, "BC");
//        c.init(Cipher.ENCRYPT_MODE, getSecretKeyFromRSA(context));
//        byte[] encodedBytes = new byte[0];
//        try {
//            encodedBytes = c.doFinal(input);
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        }
//
//        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
//    }
//    public String decrypt(Context context, byte[] encrypted) throws Exception {
//        Cipher c = Cipher.getInstance(AES_MODE, "BC");
//        c.init(Cipher.DECRYPT_MODE, getSecretKeyFromRSA(context));
//        byte[] decodedBytes = c.doFinal(encrypted);
//        return Base64.encodeToString(decodedBytes, Base64.DEFAULT);
//    }
//    private  byte[]  rsaDecrypt(byte[] encrypted) throws Exception {
//        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(ALIAS_NAME, null);
//        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
//        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
//        CipherInputStream cipherInputStream = new CipherInputStream(
//                new ByteArrayInputStream(encrypted), output);
//        ArrayList<Byte> values = new ArrayList<>();
//        int nextByte;
//        while ((nextByte = cipherInputStream.read()) != -1) {
//            values.add((byte)nextByte);
//        }
//
//        byte[] bytes = new byte[values.size()];
//        for(int i = 0; i < bytes.length; i++) {
//            bytes[i] = values.get(i).byteValue();
//        }
//        return bytes;
//    }
}
