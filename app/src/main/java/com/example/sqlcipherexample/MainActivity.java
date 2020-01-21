package com.example.sqlcipherexample;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;


public class MainActivity extends AppCompatActivity {
    EditText edtSecret;
    TextView textView, displayText;
    Button btnEncrypt, btnDecrypt;
    private AppPreference appPreference = null;
    EncryptionApi18AndAbove encryptionApi18AndAbove = null;// = new EncryptionApi18AndAbove(MainActivity.this);
    EnccryptionOverAPI23 enccryptionOverAPI23 = null; //new EnccryptionOverAPI23(MainActivity.this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        appPreference = new AppPreference(MainActivity.this);
        try {
//            enccryptionOverAPI23.generateSecretKeyDemo();
            receieveIntentData();
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
        initViews();
        performAction();
    }

    private void receieveIntentData() {
        Intent intent = this.getIntent();
        SealedObject sealedObject = (SealedObject) intent.getSerializableExtra("Object");
        byte[] iv = intent.getByteArrayExtra("IV");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            enccryptionOverAPI23 = new EnccryptionOverAPI23(MainActivity.this);
            SecretKey key = enccryptionOverAPI23.getSecretKey();
            Cipher cipher = enccryptionOverAPI23.getCipherForDecrypt(key, iv);
            try {
                Employee em2 = (Employee) sealedObject.getObject(cipher);
                LogUtils.debug(em2.name);
            } catch (Exception e) {
                LogUtils.debug(e.toString());
            }
        } else {
            encryptionApi18AndAbove =  new EncryptionApi18AndAbove(MainActivity.this);
            PrivateKey privateKey = encryptionApi18AndAbove.getPrivateKeyForDecrypt();
            Cipher cipher = encryptionApi18AndAbove.getCipherForDecrypt(privateKey);
            try {
                Employee em2 = (Employee) sealedObject.getObject(cipher);
                LogUtils.debug(em2.name);
            } catch (Exception e) {
                LogUtils.debug(e.toString());
            }
        }

    }

    private void performAction() {
        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    LogUtils.debug(Arrays.toString(edtSecret.getText().toString().getBytes()));
                    enccryptionOverAPI23.encrypt(edtSecret.getText().toString().getBytes());
                } else {
                    LogUtils.debug("RSA ENTRY CIPHERTEXT: " + encryptionApi18AndAbove.encrypt(edtSecret.getText().toString()));
                }
            }
        });

        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    LogUtils.debug("AES PLAINTEXT:" + enccryptionOverAPI23.decrypt());
                } else {
                    LogUtils.debug("RSA ENTRY PLAINTEXT: " + encryptionApi18AndAbove.decrypt(appPreference.getMobileNumber()));
                }
            }
        });
    }

    private void initViews() {
        edtSecret = findViewById(R.id.edt_secret);
        textView = findViewById(R.id.textView2);
        btnEncrypt = findViewById(R.id.btn_encrypt);
        btnDecrypt = findViewById(R.id.btn_decrypt);
        displayText = findViewById(R.id.text_display);
    }
}
