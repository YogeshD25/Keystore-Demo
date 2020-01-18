package com.example.sqlcipherexample;

import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;


public class MainActivity extends AppCompatActivity {
    private static final String TAG = "Keystore Android Demo";
    private static final String SAMPLE_ALIAS = "EntryPoint";
    EditText edtSecret;
    TextView textView, displayText;
    Button btnEncrypt, btnDecrypt;
    public static final String Name = "nameKey";
    public static final String Email = "emailKey";
    String temp = "";
    EncryptionApi18AndAbove encryptionApi18AndAbove = new EncryptionApi18AndAbove(MainActivity.this);
    EnccryptionOverAPI23 enccryptionOverAPI23 = new EnccryptionOverAPI23(MainActivity.this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        //shredPrefDemo();
        initViews();
        performAction();


       // InitializeSQLCipher();
    }

    private void shredPrefDemo() {
        SharedPreferences pref = getApplicationContext().getSharedPreferences("MyPref", 0); // 0 - for private mode
        SharedPreferences.Editor editor = pref.edit();
        String n = "ABCD";
        String e = "PQRS";
        editor.putString(Name, n);
        editor.putString(Email, e);
        editor.apply();
        Toast.makeText(this, pref.getString(Name,"asjjd"), Toast.LENGTH_SHORT).show();
        Toast.makeText(this, pref.getString(Email,"asjjd"), Toast.LENGTH_SHORT).show();

        editor.remove(Name); // will delete key name
        editor.remove(Email); // will delete key email
        editor.apply();
    }

    private void performAction() {
        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

                }else{
                    Log.d("MYAPP: ",encryptionApi18AndAbove.encrypt(edtSecret.getText().toString()));
                }
                //encryptText();
            }
        });

        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                decryptText();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                }else{
                    Log.d("MYAPP : ",edtSecret.getText().toString()+" :: "+encryptionApi18AndAbove.decrypt(temp));
                }
            }
        });
    }

    private void initViews() {
        edtSecret =  findViewById(R.id.edt_secret);
        textView = findViewById(R.id.textView2);
        btnEncrypt =  findViewById(R.id.btn_encrypt);
        btnDecrypt = findViewById(R.id.btn_decrypt);
        displayText =  findViewById(R.id.text_display);
    }

//    private void decryptText() {
//        try {
//            displayText.setText(decryptor
//                    .decryptData(SAMPLE_ALIAS, encryptor.getEncryption(), encryptor.getIv()));
//        } catch (UnrecoverableEntryException | NoSuchAlgorithmException |
//                KeyStoreException | NoSuchPaddingException | NoSuchProviderException |
//                IOException | InvalidKeyException e) {
//            Log.e(TAG, "decryptData() called with: " + e.getMessage(), e);
//        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void encryptText() {
//
//        try {
//            final byte[] encryptedText = encryptor
//                    .encryptText(SAMPLE_ALIAS, edtSecret.getText().toString());
//            displayText.setText(Base64.encodeToString(encryptedText, Base64.DEFAULT));
//        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException |
//                KeyStoreException | IOException | NoSuchPaddingException | InvalidKeyException e) {
//            Log.e(TAG, "onClick() called with: " + e.getMessage(), e);
//        } catch (InvalidAlgorithmParameterException | SignatureException |
//                IllegalBlockSizeException | BadPaddingException e) {
//            e.printStackTrace();
//        }
//    }
//
//
//    private void InitializeSQLCipher() {
//        SQLiteDatabase.loadLibs(this);
//        File databaseFile = getDatabasePath("demo.db");
//        databaseFile.mkdirs();
//        databaseFile.delete();
//        SQLiteDatabase database = SQLiteDatabase.openOrCreateDatabase(databaseFile, "test123", null);
//        database.execSQL("create table t1(a, b)");
//        database.execSQL("insert into t1(a, b) values(?, ?)", new Object[]{"one for the money",
//                "two for the show"});
//    }
}
