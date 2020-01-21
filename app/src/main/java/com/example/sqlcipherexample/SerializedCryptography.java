package com.example.sqlcipherexample;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SerializedCryptography extends AppCompatActivity {
    Button intentPass;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_serialized_cryptography);
        intentPass = findViewById(R.id.buttonIntent);
        intentPass.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    Employee em1 = new Employee("Yogesh", "123");
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        final EnccryptionOverAPI23 enccryptionOverAPI23 = new EnccryptionOverAPI23(SerializedCryptography.this);
                        SecretKey secretKey = enccryptionOverAPI23.getSecretKey();
                        Cipher cipherEnc = enccryptionOverAPI23.getCipherForEncrypt(secretKey);
                        byte[] ivBytes = cipherEnc.getIV();


                        // create sealed object
                        SealedObject sealedEm1 = new SealedObject(em1, cipherEnc);
                        Intent intent =  new Intent(SerializedCryptography.this,MainActivity.class);
                        intent.putExtra("Object",sealedEm1);
                        intent.putExtra("IV",ivBytes);
                        startActivity(intent);
                    }else{
                        final EncryptionApi18AndAbove encryptionApi18AndAbove = new EncryptionApi18AndAbove(SerializedCryptography.this);
                        PublicKey publicKey = encryptionApi18AndAbove.getPublicKeyForEncrypt();
                        Cipher cipherEnc = encryptionApi18AndAbove.getCipherForEncrypt(publicKey);
                        byte[] bytes={11,11,11};

                        SealedObject sealedEm1 = new SealedObject(em1, cipherEnc);
                        Intent intent =  new Intent(SerializedCryptography.this,MainActivity.class);
                        intent.putExtra("Object",sealedEm1);
                        intent.putExtra("IV",bytes);
                        startActivity(intent);
                    }

                } catch (Exception e) {
                    LogUtils.debug(e.toString());
                }
            }
        });
    }
}



