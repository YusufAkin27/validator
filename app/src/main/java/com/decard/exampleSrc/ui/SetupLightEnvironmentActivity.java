package com.decard.exampleSrc.ui;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.decard.exampleSrc.MainActivity;
import com.decard.exampleSrc.desfire.DESFireEV3;
import com.decard.exampleSrc.desfire.ev1.model.command.IsoDepWrapper;
import com.decard.exampleSrc.desfire.ev3.ApplicationKeySettings;
import com.decard.exampleSrc.desfire.ev3.DesfireAuthenticateLegacy;
import com.decard.exampleSrc.desfire.ev3.EV3;
import com.decard.exampleSrc.desfire.ev3.FileSettings;
import com.decard.exampleSrc.desfire.util.Utils;
import com.decard.exampleSrc.reader.P18QDesfireEV;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.textfield.TextInputEditText;

import java.io.IOException;

import com.decard.exampleSrc.R;
public class SetupLightEnvironmentActivity extends AppCompatActivity  {

    private static final String TAG = SetupLightEnvironmentActivity.class.getSimpleName();

    /**
     * UI elements
     */

    private TextInputEditText output;
    private TextInputLayout outputLayout;
    private Button btnDiscover;
    private Button moreInformation;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);


    /**
     * NFC handling
     */

    private IsoDep isoDep;
    private byte[] tagIdByte;
    private DESFireEV3 desfireEv3;
    private DesfireAuthenticateLegacy desfireD40;
    private FileSettings fileSettings;
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup_light_environment);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etSetupLightEnvironmentOutput);
        outputLayout = findViewById(R.id.etSetupLightEnvironmentOutputLayout);
        moreInformation = findViewById(R.id.btnSetupLightEnvironmentMoreInformation);
        btnDiscover = findViewById(R.id.btnDiscover);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(SetupLightEnvironmentActivity.this, getResources().getString(R.string.more_information_setup_light_environment));
            }
        });        /**
         * discover desfire ev card
         */
        btnDiscover.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                P18QDesfireEV p18QDesfireEV = new P18QDesfireEV();
                if (p18QDesfireEV.discoverEVCard()) {
                    onTagDiscovered(p18QDesfireEV);
                }else{
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                    writeToUiAppendBorderColor("could not found DesfireEV card, aborted", COLOR_RED);
                }
            }
        });
    }

    private void runSetupLightEnvironment() {
        clearOutputFields();
        String logString = "runSetupDESFireLightEnvironment";
        writeToUiAppend(output, logString);
        /**
         * the method will do these 8 steps to prepare the tag for test usage
         * 1) select Master Application ("000000")
         * 2) authenticate with MASTER_APPLICATION_KEY_DES_DEFAULT ("0000000000000000")
         * 3) format PICC
         * 4) create a new application ("E1E2E3")
         * 5) select the new application ("E1E2E3")
         * 6) create a new file set consisting of 5 files: 3 Standard files, 1 Value file and 1 Cyclic Record file
         * 7) authenticate the application with the Application Master Key (AES default)
         * 8) create a new Transaction MAC file
         */

        boolean success;
        byte[] errorCode;
        String errorCodeReason = "";
        writeToUiAppend(output, "");

        // the 'formatPicc' methods runs the 3 tasks in once

        writeToUiAppend("step 1: select Master Application with ID 0x000000");
        writeToUiAppend("step 2: authenticate with default DES Master Application Key");
        writeToUiAppend("step 3: format the PICC");
        ApplicationKeySettings applicationKeySettings = desfireEv3.getApplicationKeySettings();
        int keyType = applicationKeySettings.getKeyType();

        if (keyType == 0x00){
            success = desfireEv3.desfireD40.formatPicc();
            errorCode = desfireEv3.desfireD40.getErrorCode();
        }else {
            success = desfireEv3.formatPicc(keyType);
            errorCode = desfireEv3.getErrorCode();
        }
        if (success) {
            writeToUiAppendBorderColor("format of the PICC SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("format of the PICC FAILURE, aborted", COLOR_RED);
            return;
        }
        // If there are any failures on creating the activity isn't ending because the application or file can exist
        writeToUiAppend("step 4: create a new application (\"E1E2E3\")");
        success = desfireEv3.createApplicationAesIso(Constants.LIGHT_APPLICATION_IDENTIFIER_AES, Constants.LIGHT_APPLICATION_ISO_FILE_ID_DEFAULT, Constants.LIGHT_APPLICATION_DF_NAME_DEFAULT, Constants.LIGHT_APPLICATION_NUMBER_OF_KEYS);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create a new application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create a new application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            //return;
        }

        writeToUiAppend("step 5: select the new application (\"E1E2E3\")");
        success = desfireEv3.selectApplicationIsoByDfName(Constants.LIGHT_APPLICATION_DF_NAME_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select the new application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("select the new application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            //return;
        }

        writeToUiAppend("step 6: create a new file set with 3 Standard, 1 Value and 1 Cyclic Record file in different comm modes");
        success = createLightFileSet();
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create a new file set SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create a new file set FAILURE, aborted", COLOR_RED);
            //return;
        }

        writeToUiAppend("step 7: authenticate with the application master key");
        success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("authenticate with the application master key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("authenticate with the application master key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // the creation needs a preceding authentication with the application master key
        writeToUiAppend("step 8: create a TransactionMAC file");
        success = desfireEv3.createATransactionMacFileFullNewLight(Constants.LIGHT_TRANSACTION_MAC_FILE_21_FULL_NUMBER, DESFireEV3.CommunicationSettings.Full, 3, 0, 1, true, Constants.TRANSACTION_MAC_KEY_AES_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create a TransactionMAC file SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create a TransactionMAC file FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend(output, "");
        vibrateShort();
    }

    private boolean createLightFileSet() {
        Log.d(TAG, "createLightFileSet");
        boolean createStandardFile00Full = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_00_FULL_NUMBER, Constants.LIGHT_STANDARD_FILE_00_FULL_ISO_FILE_ID, DESFireEV3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_00, 256, false);
        Log.d(TAG, "createStandardFile00Full result: " + createStandardFile00Full);
        boolean createCyclicRecordFileFull = desfireEv3.createACyclicRecordFileIso(Constants.LIGHT_CYCLIC_RECORD_FILE_01_FULL_NUMBER, Constants.LIGHT_CYCLIC_RECORD_FILE_01_FULL_ISO_FILE_ID, DESFireEV3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_01, 16, 5);
        Log.d(TAG, "createCyclicRecordFileFull result: " + createCyclicRecordFileFull);
        boolean createValueFile03Full = desfireEv3.createAValueFile(Constants.LIGHT_VALUE_FILE_03_FULL_NUMBER, DESFireEV3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_03, 0,2147483647, 0,false);
        Log.d(TAG, "createValueFileFull result: " + createValueFile03Full);
        boolean createStandardFile04Full = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_04_FULL_NUMBER, Constants.LIGHT_STANDARD_FILE_04_FULL_ISO_FILE_ID, DESFireEV3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_04, 256, false);
        Log.d(TAG, "createStandardFile04Full result: " + createStandardFile04Full);

        boolean createStandardFile31Plain = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_31_PLAIN_NUMBER, Constants.LIGHT_STANDARD_FILE_31_PLAIN_ISO_FILE_ID , DESFireEV3.CommunicationSettings.Plain, Constants.LIGHT_FILE_ACCESS_RIGHTS_31, 32, false);
        Log.d(TAG, "createStandardFile31Plain result: " + createStandardFile31Plain);
        return true;
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    /*
    @Override
    public void onTagDiscovered(Tag tag) {
        clearOutputFields();
        writeToUiAppend("NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }
                desfireEv3 = new DESFireEV3(isoDep); // true means all data is logged

                isDesfireEv3 = desfireEv3.checkForDESFireEv3();
                if (!isDesfireEv3) {
                    writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                    return;
                }
                desfireD40 = new DesfireAuthenticateLegacy(isoDep, false);

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);
                runSetupLightEnvironment();

            }
        } catch (IOException e) {
            writeToUiAppendBorderColor("IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }
    }
    */
    public void onTagDiscovered(IsoDepWrapper isoDep) {
        clearOutputFields();
        writeToUiAppend("NFC tag discovered");
        try {
            // Make a Vibration
            vibrateShort();

            runOnUiThread(() -> {
                output.setText("");
                output.setBackgroundColor(getResources().getColor(R.color.white));
            });
            isoDep.connect();
            if (!isoDep.isConnected()) {
                writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                isoDep.close();
                return;
            }
            desfireEv3 = new DESFireEV3(isoDep); // true means all data is logged

            isDesfireEv3 = desfireEv3.checkForDESFireEv3();
            if (!isDesfireEv3 && !desfireEv3.checkForDESFireEv2()) {
                writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                return;
            }
            desfireD40 = new DesfireAuthenticateLegacy(isoDep, true);

            writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);
            runSetupLightEnvironment();
        } catch (IOException e) {
            writeToUiAppendBorderColor("IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

    }

    @Override
    protected void onPause() {
        super.onPause();
    }


    /**
     * section for UI elements
     */

    private void writeToUiAppend(String message) {
        writeToUiAppend(output, message);
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void writeToUi(TextView textView, String message) {
        runOnUiThread(() -> {
            textView.setText(message);
        });
    }

    private void writeToUiAppendBorderColor(String message, int color) {
        writeToUiAppendBorderColor(output, outputLayout, message, color);
    }

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    public void showDialog(Activity activity, String msg) {
        final Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setContentView(R.layout.logdata);
        TextView text = dialog.findViewById(R.id.tvLogData);
        //text.setMovementMethod(new ScrollingMovementMethod());
        text.setText(msg);
        Button dialogButton = dialog.findViewById(R.id.btnLogDataOk);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private void clearOutputFields() {
        runOnUiThread(() -> {
            output.setText("");
        });
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        outputLayout.setBoxStrokeColorStateList(myColorList);
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * section for options menu
     */    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_desfire_activity_main, menu);

        MenuItem mFormatPicc = menu.findItem(R.id.action_format_picc);
        mFormatPicc.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, FormatPiccActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mSetupTestEnvironment = menu.findItem(R.id.action_setup_test_environment);
        mSetupTestEnvironment.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, SetupTestEnvironmentActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mPersonalize = menu.findItem(R.id.action_personalize);
        mPersonalize.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, PersonalizeActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mCreateApplication = menu.findItem(R.id.action_create_application);
        mCreateApplication.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, CreateApplicationActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mCreateFile = menu.findItem(R.id.action_create_file);
        mCreateFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, CreateFileActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mSetupLightEnvironment = menu.findItem(R.id.action_setup_light_environment);
        mSetupLightEnvironment.setEnabled(false);

        MenuItem mExportTextFile = menu.findItem(R.id.action_export_text_file);
        mExportTextFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportTextFile");
                //exportTextFile();
                return false;
            }
        });
        MenuItem mDesFireMain = menu.findItem(R.id.action_desfire_main);
        mDesFireMain.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, DesfireMainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupLightEnvironmentActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}