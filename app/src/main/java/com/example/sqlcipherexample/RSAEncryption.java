package com.example.sqlcipherexample;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public class RSAEncryption {

    public void testPreMEncryption(Context context)
    {
        try
        {
            //Generate a keypair and store it in the KeyStore
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 10);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias("MyKeyAlias")
                    .setSubject(new X500Principal("CN=MyKeyName, O=Android Authority"))
                    .setSerialNumber(new BigInteger(1024, new Random()))
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .setEncryptionRequired() //on API level 18, encrypted at rest, requires lock screen to be set up, changing lock screen removes key
                    .build();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(spec);
            keyPairGenerator.generateKeyPair();

            //Encryption test


            final byte[] encryptedBytes = rsaEncrypt("My secret string!".getBytes("UTF-8"));
            final byte[] decryptedBytes = rsaDecrypt(encryptedBytes);
            final String decryptedString = new String(decryptedBytes, "UTF-8");
            Log.e("MyApp", "Decrypted string is " + decryptedString);
        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }
    }
    public byte[] rsaEncrypt(final byte[] decryptedBytes)
    {
        byte[] encryptedBytes = null;
        try
        {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("MyKeyAlias", null);
            final RSAPublicKey publicKey = (RSAPublicKey)privateKeyEntry.getCertificate().getPublicKey();

            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(decryptedBytes);
            cipherOutputStream.close();

            encryptedBytes = outputStream.toByteArray();

        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }
        return encryptedBytes;
    }
    public byte[] rsaDecrypt(final byte[] encryptedBytes)
    {
        byte[] decryptedBytes = null;
        try
        {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("MyKeyAlias", null);
            final RSAPrivateKey privateKey = (RSAPrivateKey)privateKeyEntry.getPrivateKey();

            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            final CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encryptedBytes), cipher);
            final ArrayList<Byte> arrayList = new ArrayList<>();
            int nextByte;
            while ( (nextByte = cipherInputStream.read()) != -1 )
            {
                arrayList.add((byte)nextByte);
            }

            decryptedBytes = new byte[arrayList.size()];
            for(int i = 0; i < decryptedBytes.length; i++)
            {
                decryptedBytes[i] = arrayList.get(i);
            }
        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }

        return decryptedBytes;
    }

    public String rsaDecryptToString(final byte[] encryptedBytes)
    {
        byte[] decryptedBytes = null;
        try
        {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("MyKeyAlias", null);
            final RSAPrivateKey privateKey = (RSAPrivateKey)privateKeyEntry.getPrivateKey();

            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            final CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encryptedBytes), cipher);
            final ArrayList<Byte> arrayList = new ArrayList<>();
            int nextByte;
            while ( (nextByte = cipherInputStream.read()) != -1 )
            {
                arrayList.add((byte)nextByte);
            }

            decryptedBytes = new byte[arrayList.size()];
            for(int i = 0; i < decryptedBytes.length; i++)
            {
                decryptedBytes[i] = arrayList.get(i);
            }
        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }

        return decryptedBytes.toString();
    }

    public String rsaEncryptToString(final byte[] decryptedBytes)
    {
        byte[] encryptedBytes = null;
        try
        {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("MyKeyAlias", null);
            final RSAPublicKey publicKey = (RSAPublicKey)privateKeyEntry.getCertificate().getPublicKey();

            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(decryptedBytes);
            cipherOutputStream.close();

            encryptedBytes = outputStream.toByteArray();

        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }
        return new String(encryptedBytes);
    }
    public String encryptText(String plainText){

            String encryptedString ="";
        try {
            encryptedString = rsaEncryptToString(plainText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }
    public String decryptText(String cipherText){

        String decryptedString ="";
        try {
            decryptedString = rsaDecryptToString(cipherText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedString;
    }





}
