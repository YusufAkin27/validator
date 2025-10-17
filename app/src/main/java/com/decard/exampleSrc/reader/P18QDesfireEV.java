/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.reader;

import android.os.SystemClock;
import android.util.Log;

import com.decard.NDKMethod.BasicOper;
import com.decard.exampleSrc.desfire.ev1.model.command.IsoDepWrapper;
import com.decard.exampleSrc.mifarePlus.IMifarePlusIO;
import com.decard.exampleSrc.samav2.ByteArrayTools;

import java.io.IOException;

/**
 *
 * @author cfsolano
 */
public class P18QDesfireEV implements IsoDepWrapper {
    private static final String TAG = P18QDesfireEV.class.getSimpleName();

    public final int DISCOVERY_CARD_TYPEA = 0;
    public final int DISCOVERY_CARD_TYPEB = 1;
    public final int DISCOVERY_MODE_IDLE_CARD = 0;
    public final int DISCOVERY_MODE_ALL_CARD = 1;
    public final String desfireATQA = "4403";

    public byte [] transceive(byte [] apdu) throws  IOException {
        String[] resultArr;
        String APDU = ByteArrayTools.toHexString(apdu,true);
        Log.i(TAG, "PICC apdu--->" + APDU);
        resultArr = BasicOper.dc_pro_commandhex(APDU, 7).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            byte[] rpdu = ByteArrayTools.hexStringToByteArray(resultArr[1]);
            Log.i(TAG,"PICC rpdu<---" + resultArr[1]);// + "/" + ByteArrayTools.toHexString(rpdu,true));
            return rpdu;
        } else {
            String error = "PICC rpdu " + "error code = " + resultArr[0] + " error msg = " + resultArr[1];
            //Log.i(TAG,"PICC rpdu " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            throw new IOException(error);
        }
    }

    private void rfFieldOnOff(boolean on) {
        if (on)
            BasicOper.dc_reset();// RF filed on
        else {
            String[] resultArr = BasicOper.dc_reset_close().split("\\|", -1);// RF filed off
            //Log.i(TAG,"dc_reset_close " + resultArr[0]);
            SystemClock.sleep(50);
        }
    }
    private int detectPiccCpuCard() {
        final int ATS = 3;
        rfFieldOnOff(false);
        String[] resultArr = BasicOper.dc_reset().split("\\|", -1);
        if (!resultArr[0].equals("0000")) {
            return -1;
        }
        resultArr = BasicOper.dc_config_card(DISCOVERY_CARD_TYPEA).split("\\|", -1);
        if (!resultArr[0].equals("0000")) {
            return -1;
        }
        resultArr = BasicOper.dc_card_n_hex(DISCOVERY_MODE_ALL_CARD).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.i(TAG, "dc_card_n_hex " + "success card sn = " + resultArr[1]);
        } else {
            Log.e(TAG, "dc_card_n_hex " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            Log.e(TAG, "Test TypeA error");
            return -12;
        }
        resultArr = BasicOper.dc_pro_resethex().split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.e(TAG, "dc_pro_resethex " + "success ATR/ATS = " + resultArr[1]);
            //return 0;
        } else {
            Log.e(TAG, "dc_pro_resethex " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return -13;
        }
        resultArr = BasicOper.dc_GetIso14443Attribute(ATS).split("\\|", -1);
        if (!resultArr[0].equals("0000") || resultArr[1].startsWith("3B")) {
            Log.e(TAG, "dc_pro_resethex not CPU card.");
            return -16;
        }
        return 0;
    }
    private String[] getPICCAtrribute() {
        final int ATQA = 1;
        final int SAK = 2;
        final int ATS = 3;
        String attribute[] = new String[]{"", "", ""};
        String[] resultArr = BasicOper.dc_GetIso14443Attribute(ATQA).split("\\|", -1);

        if (resultArr[0].equals("0000")) {
            Log.e(TAG,"dc_GetIso14443Attribute " + "success atqa:" + resultArr[1]);
            attribute[0] = resultArr[1];
        } else {
            Log.e(TAG,"dc_GetIso14443Attribute " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return attribute;
        }
        resultArr = BasicOper.dc_GetIso14443Attribute(SAK).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.e(TAG,"dc_GetIso14443Attribute " + "success sak:" + resultArr[1]);
            attribute[1] = resultArr[1];
        } else {
            Log.e(TAG,"dc_GetIso14443Attribute " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return attribute;
        }
        resultArr = BasicOper.dc_GetIso14443Attribute(ATS).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.e(TAG,"dc_GetIso14443Attribute " + "success ats:" + resultArr[1]);
            attribute[2] = resultArr[1];
        } else {
            Log.e(TAG,"dc_GetIso14443Attribute " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return attribute;
        }
        return attribute;
    }
    public boolean discoverEVCard(){
        int st = detectPiccCpuCard();
        if (st != 0) {
            Log.e(TAG,"discoverEVCard error");
            return false;
        }
        // uid sak and atqa could be returned after card detected
        String[] atrribute = getPICCAtrribute();
        if (!atrribute[0].equals(desfireATQA)) {
            Log.e(TAG,"Not DesFireEV2 card");
            return false;
        }
        return true;
    }
    public boolean isConnected(){ return true;}
    public void connect() throws IOException{}
    public void close() throws IOException{}
}
