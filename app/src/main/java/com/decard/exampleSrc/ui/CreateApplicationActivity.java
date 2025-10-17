package com.decard.exampleSrc.ui;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
//import android.nfc.NfcAdapter;
//import android.nfc.Tag;
//import android.nfc.tech.IsoDep;
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
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.decard.exampleSrc.MainActivity;
import com.decard.exampleSrc.desfire.DESFireEV3;
import com.decard.exampleSrc.desfire.ev1.model.command.IsoDepWrapper;
import com.decard.exampleSrc.desfire.ev3.DesfireAuthenticateLegacy;
import com.decard.exampleSrc.desfire.ev3.EV3;
import com.decard.exampleSrc.desfire.util.Utils;
import com.decard.exampleSrc.reader.P18QDesfireEV;
import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.util.Arrays;
import com.decard.exampleSrc.R;

public class CreateApplicationActivity extends AppCompatActivity  {

    private static final String TAG = CreateApplicationActivity.class.getSimpleName();

    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output, applicationIdentifier, numberOfKeys, carAppKey;
    private com.google.android.material.textfield.TextInputLayout outputLayout;
    private CheckBox masterKeyIsChangable, masterKeyAuthenticationNeededDirListing, masterKeyAuthenticationNeededCreateDelete, masterKeySettingsChangeAllowed;
    private Button btnDiscover;
    private Button moreInformation;

    private RadioButton rbDoNothing, rbChangeAppKeysToChanged, rbChangeAppKeysToDefault, rbChangeMasterAppKeyToChanged, rbChangeMasterAppKeyToDefault;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};

    /**
     * NFC handling
     */
    //private IsoDep isoDep;
    private byte[] tagIdByte;

    private DESFireEV3 desfireEv3;
    private DesfireAuthenticateLegacy desfireLegacy;

    private byte[] errorCode;
    private String errorCodeReason = "";
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_create_application);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etCreateApplicationOutput);
        outputLayout = findViewById(R.id.etCreateApplicationOutputLayout);
        moreInformation = findViewById(R.id.btnCreateApplicationMoreInformation);

        applicationIdentifier = findViewById(R.id.etCreateApplicationAid);
        numberOfKeys = findViewById(R.id.etCreateApplicationNumberOfKeys);
        carAppKey = findViewById(R.id.etCreateApplicationCarKeyNumber);
        masterKeyIsChangable = findViewById(R.id.cbCreateApplicationBit0MasterKeyIsChangeable);
        masterKeyAuthenticationNeededDirListing = findViewById(R.id.cbCreateApplicationBit1MasterKeyAuthenticationNeededDirListing);
        masterKeyAuthenticationNeededCreateDelete = findViewById(R.id.cbCreateApplicationBit2MasterKeyAuthenticationNeededCreateDelete);
        masterKeySettingsChangeAllowed = findViewById(R.id.cbCreateApplicationBit3MasterKeySettingsChangeAllowed);
        btnDiscover = findViewById(R.id.btnDiscover);
        RadioGroup radioGroup = findViewById(R.id.rgCreateApplication);
        radioGroup.setVisibility(View.GONE);

        checkboxesToDefault();

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(CreateApplicationActivity.this, getResources().getString(R.string.more_information_create_application));
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

    private void runCreateApplication() {
        clearOutputFields();
        String logString = "runCreateApplication";
        writeToUiAppend(output, logString);

        // sanity checks
        String appId = applicationIdentifier.getText().toString();
        if (TextUtils.isEmpty(appId)) {
        }
        byte[] appIdBytes = Utils.hexStringToByteArray(appId);
        if (applicationIdentifier == null) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter a 6 hex characters long application identifier", COLOR_RED);
            return;
        }
        //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
        if (appIdBytes.length != 3) {
            writeToUiAppendBorderColor(output, outputLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
            return;
        }
        String numKeys = numberOfKeys.getText().toString();
        if (TextUtils.isEmpty(numKeys)) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter the number of keys in range 1..14", COLOR_RED);
            return;
        }
        int numberOfApplicationKeys = Integer.parseInt(numKeys);
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter the number of keys in range 1..14", COLOR_RED);
            return;
        }
        // no sanity check on this as it is fixed
        String carKeyNumber = carAppKey.getText().toString();
        byte carKeyByte = Byte.parseByte(carKeyNumber);
        int carKeyInt = Integer.parseInt(carKeyNumber);

        // now the funny part - the application settings - bitwise combined with carKeyByte
        /*
			bit 0 is most right bit (counted from right to left)
			bit 0 = application master key is changeable (1) or frozen (0)
			bit 1 = application master key authentication is needed for file directory access (1)
			bit 2 = application master key authentication is needed before CreateFile / DeleteFile (1)
			bit 3 = change of the application master key settings is allowed (1)
			bit 4-7 = hold the Access Rights for changing application keys (ChangeKey command)
			• 0x0: Application master key authentication is necessary to change any key (default).
			• 0x1 .. 0xD: Authentication with the specified key is necessary to change any key.
			• 0xE: Authentication with the key to be changed (same KeyNo) is necessary to change a key.
			• 0xF: All Keys (except application master key, see Bit0) within this application are frozen.
		 */
        byte appSettings = (byte) 0x00;
        if (masterKeyIsChangable.isChecked()) {
            appSettings = Utils.setBitInByte(appSettings, 0);
        } else {
            appSettings = Utils.unsetBitInByte(appSettings, 0);
        }
        // attention - the set/unset are changed due to naming
        if (masterKeyAuthenticationNeededDirListing.isChecked()) {
            appSettings = Utils.unsetBitInByte(appSettings, 1);
        } else {
            appSettings = Utils.setBitInByte(appSettings, 1);
        }
        // attention - the set/unset are changed due to naming
        if (masterKeyAuthenticationNeededCreateDelete.isChecked()) {
            appSettings = Utils.unsetBitInByte(appSettings, 2);
        } else {
            appSettings = Utils.setBitInByte(appSettings, 2);
        }
        if (masterKeySettingsChangeAllowed.isChecked()) {
            appSettings = Utils.setBitInByte(appSettings, 3);
        } else {
            appSettings = Utils.unsetBitInByte(appSettings, 3);
        }
        // now we concatenate the Car Application Key with the App Settings
        char upperNibble = Utils.byteToUpperNibble(carKeyByte);
        char lowerNibble = Utils.byteToLowerNibble(appSettings);
        byte applicationMasterSettings = Utils.nibblesToByte(upperNibble, lowerNibble);

        boolean success;
        byte[] errorCode;
        String errorCodeReason = "";
        writeToUiAppend(output, "");
        String stepString = "1 select the Master Application";
        writeToUiAppend(output, stepString);
        success = desfireEv3.selectApplicationByAid(DESFireEV3.MASTER_APPLICATION_IDENTIFIER);
        errorCode = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            if (Arrays.equals(errorCode, DESFireEV3.RESPONSE_DUPLICATE_ERROR)) {
                writeToUiAppendBorderColor(stepString + " FAILURE because application already exits", COLOR_GREEN);
            } else {
                writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
                return;
            }
        }

        stepString = "2 create the new application";
        writeToUiAppend(output, stepString);
        success = desfireEv3.createApplicationAes(appIdBytes, numberOfApplicationKeys, applicationMasterSettings);
        errorCode = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            if (Arrays.equals(errorCode, DESFireEV3.RESPONSE_DUPLICATE_ERROR)) {
                writeToUiAppendBorderColor(stepString + " FAILURE because application already exits", COLOR_GREEN);
            } else {
                writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
                return;
            }
        }
        vibrateShort();
    }


    private void checkboxesToDefault() {
        masterKeyIsChangable.setChecked(true);
        masterKeyAuthenticationNeededDirListing.setChecked(false);
        masterKeyAuthenticationNeededCreateDelete.setChecked(false);
        masterKeySettingsChangeAllowed.setChecked(true);
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
                desfireEv3 = new DESFireEV3(isoDep);
                desfireLegacy = new DesfireAuthenticateLegacy(isoDep, false);

                isDesfireEv3 = desfireEv3.checkForDESFireEv3();
                if (!isDesfireEv3) {
                    writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                    return;
                }

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);

                runCreateApplication();

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
            desfireEv3 = new DESFireEV3(isoDep);
            desfireLegacy = new DesfireAuthenticateLegacy(isoDep, true);

            isDesfireEv3 = desfireEv3.checkForDESFireEv3();
            if (!isDesfireEv3 && !desfireEv3.checkForDESFireEv2()) {
                writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                return;
            }
            writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);

            runCreateApplication();
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
     */
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_desfire_activity_main, menu);

        MenuItem mFormatPicc = menu.findItem(R.id.action_format_picc);
        mFormatPicc.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, FormatPiccActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mSetupTestEnvironment = menu.findItem(R.id.action_setup_test_environment);
        mSetupTestEnvironment.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, SetupTestEnvironmentActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mPersonalize = menu.findItem(R.id.action_personalize);
        mPersonalize.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, PersonalizeActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mCreateApplication = menu.findItem(R.id.action_create_application);
        mCreateApplication.setEnabled(false);

        MenuItem mCreateFile = menu.findItem(R.id.action_create_file);
        mCreateFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, CreateFileActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mSetupLightEnvironment = menu.findItem(R.id.action_setup_light_environment);
        mSetupLightEnvironment.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, SetupLightEnvironmentActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mExportTextFile = menu.findItem(R.id.action_export_text_file);
        mExportTextFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportTextFile");
               // exportTextFile();
                return false;
            }
        });
        MenuItem mDesFireMain = menu.findItem(R.id.action_desfire_main);
        mDesFireMain.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, DesfireMainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(CreateApplicationActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}