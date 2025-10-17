/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.reader;

import android.util.Log;

import com.decard.NDKMethod.BasicOper;
import com.decard.exampleSrc.desfire.ev1.model.command.IsoDepAdapter;
import com.decard.exampleSrc.desfire.ev1.model.command.IsoDepWrapper;
import com.decard.exampleSrc.desfire.ev1.model.command.Utils;
import com.decard.exampleSrc.mifarePlus.IMifarePlusIO;
import com.decard.exampleSrc.samav2.ByteArrayTools;

/**
 *
 * @author cfsolano
 */
public class P18QMifareUltraLight implements IMifarePlusIO {
    private static final String TAG = P18QMifarePlus.class.getSimpleName();

    public static final byte MFUL_RESP_ACK = (byte)0x0A;   /**< MIFARE Ultralight ACK response code */
    public P18QMifareUltraLight(){

    }
    public byte[] sendApduControlCommand(byte[] apdu){
        return sendApduCommand(apdu);
    }

    private boolean checkCrc(byte[] response){

        if((response == null) || (response.length < 3))
            return false;
        byte[] crc = Utils.crc16(response);

        Log.i("crc16 ", "response: " + Utils.getHexString(response) + " crc:" + Utils.getHexString(crc));

        return Utils.getHexString(crc).equals("0000");
    }

    public byte [] sendApduCommand(byte [] apdu) {
        String[] resultArr;
        String APDU = ByteArrayTools.toHexString(apdu,true);
        Log.i(TAG, "PICC apdu--->" + APDU);
        resultArr = BasicOper.dc_pro_commandsource_int(APDU, 7).split("\\|", -1);

        if (resultArr[0].equals("0000")) {
            byte[] rpdu = ByteArrayTools.hexStringToByteArray(resultArr[1]);
            if((rpdu != null) && (rpdu.length == 1) &&rpdu[0] == MFUL_RESP_ACK) {
                return rpdu;
            }
            if(!checkCrc(rpdu)) {
                Log.i(TAG,"PICC rpdu<---" + resultArr[1] + " crc error");
                return null;
            }
            Log.i(TAG,"PICC rpdu<---" + resultArr[1]);// + "/" + ByteArrayTools.toHexString(rpdu,true));
            return ByteArrayTools.hexStringToByteArray(resultArr[1].substring(0,resultArr[1].length() - 4));
        } else {
            Log.i(TAG,"PICC rpdu " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return null;
        }
    }

    public boolean isConnected(){return true;}

    /**
     * connect (START) to SAM
     * @return
     */
    public boolean connectCard() {
        return true;
    }

    public boolean disconnectCard() {
        return true;
    }


    /**
     * @brief  设置当前接触式卡座。
     * @par    说明：
     * 设置当前接触式卡座为指定卡座，用于多卡座切换卡操作。
     * @param[in] icdev 设备标识符。
     * @param[in] _Byte 卡座编号。
     * @n 0x0C - 附卡座/接触式CPU1卡座。
     * @n 0x0B - 接触式CPU2卡座。
     * @n 0x0D - SAM1卡座。
     * @n 0x0E - SAM2卡座。
     * @n 0x0F - SAM3卡座。
     * @n 0x11 - SAM4卡座。
     * @n 0x12 - SAM5卡座。
     * @n 0x13 - SAM6卡座/ESAM芯片。
     * @n 0x14 - SAM7卡座。
     * @n 0x15 - SAM8卡座。
     * @n 0x16~0xFF - 其它卡座。
     * @return <0表示失败，==0表示成功。
     */
    /**
     * get ATR
     * @return ATR
     */
    public byte[] getATR(){
        String[] resultArr;
        int mode = 1; // 0:IDLE 1:ALL
        resultArr = BasicOper.dc_card_n_hex(mode).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.i(TAG,"dc_card_n_hex success," + "ATR/ATS = " + resultArr[1]);
            return resultArr[1].getBytes();
        } else {
            Log.i(TAG,"dc_card_n_hex " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return null;
        }
    }



}
