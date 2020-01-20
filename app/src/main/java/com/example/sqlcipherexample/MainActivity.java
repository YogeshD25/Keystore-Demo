package com.example.sqlcipherexample;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.util.Arrays;


public class MainActivity extends AppCompatActivity {
    EditText edtSecret;
    TextView textView, displayText;
    Button btnEncrypt, btnDecrypt;
    private AppPreference appPreference = null;
    EncryptionApi18AndAbove encryptionApi18AndAbove = new EncryptionApi18AndAbove(MainActivity.this);
    EnccryptionOverAPI23 enccryptionOverAPI23 = new EnccryptionOverAPI23(MainActivity.this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        appPreference = new AppPreference(MainActivity.this);
        try {
            enccryptionOverAPI23.generateSecretKeyDemo();
        } catch (Exception e) {
            LogUtils.debug(e.toString());
        }
        initViews();
        performAction();
    }

    private void performAction() {
        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    LogUtils.debug(Arrays.toString(edtSecret.getText().toString().getBytes()));
                    enccryptionOverAPI23.encrypt(edtSecret.getText().toString().getBytes(),MainActivity.this);
                } else {
                    LogUtils.debug("RSA ENTRY CIPHERTEXT: " + encryptionApi18AndAbove.encrypt(edtSecret.getText().toString()));
                }
            }
        });

        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    LogUtils.debug("AES PLAINTEXT:" + enccryptionOverAPI23.decrypt(MainActivity.this));
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
