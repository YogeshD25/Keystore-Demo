package com.example.sqlcipherexample;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public class EncryptionApi18AndAbove {
    private Context context;
    private KeyStore keyStore;
    private static String ALAS = "alias";
    private static String RSATRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static String ANDROIDKEYSTORE = "AndroidKeyStore";
    private static String ALGORITHM = "RSA";
    private AppPreference appPreference = null;

    public EncryptionApi18AndAbove(Context context) {
        this.context = context;
        try {
            keyStore = KeyStore.getInstance(ANDROIDKEYSTORE);
            keyStore.load(null);
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
    }

    private String createNewKeys(String alias, Context context) {
        try {
            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(alias)
                        .setSubject(new X500Principal("CN=NeML, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, ANDROIDKEYSTORE);
                generator.initialize(spec);
                generator.initialize(spec);
                generator.generateKeyPair();
            }
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
        return alias;
    }

    public String encrypt(String text) {
        if (text == null || text.length() == 0) {
            return text;
        }
        try {
            appPreference = new AppPreference(context);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(createNewKeys(ALAS, context), null);
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
            Cipher inCipher = Cipher.getInstance(RSATRANSFORMATION);
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(text.getBytes("UTF-8"));
            cipherOutputStream.close();
            appPreference.setMobileNumber(Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT));

            return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT);
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
        return text;
    }

    public String decrypt(String text) {
        if (text == null || text.length() == 0) {
            return text;
        }
        try {
            appPreference = new AppPreference(context);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(createNewKeys(ALAS, context), null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance(RSATRANSFORMATION);
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(text, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }
            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }
            return new String(bytes, 0, bytes.length, "UTF-8");

        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
        return text;
    }
}