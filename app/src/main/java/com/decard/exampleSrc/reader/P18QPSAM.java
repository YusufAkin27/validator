/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.reader;

import android.util.Log;

import com.decard.NDKMethod.BasicOper;
import com.decard.exampleSrc.samav2.ByteArrayTools;
import com.decard.exampleSrc.samav2.ISamAv2IO;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 *
 * @author cfsolano
 */
public class P18QPSAM implements ISamAv2IO {
    private static final String TAG = P18QPSAM.class.getSimpleName();
     private int psamSlot;

    public P18QPSAM(int psamSlot){

        this.psamSlot = psamSlot;
    }

    public byte [] sendApduCommand(byte [] apdu) {
        String[] resultArr;
        String APDU = ByteArrayTools.toHexString(apdu,true);
        Log.i(TAG, "apdu--->" + APDU);

        resultArr = BasicOper.dc_TransmitApdu(0xff,APDU).split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            byte[] rpdu = ByteArrayTools.hexStringToByteArray(resultArr[1]);
            Log.i(TAG,"rpdu<---" + resultArr[1]);// + "/" + ByteArrayTools.toHexString(rpdu,true));
            return rpdu;
        } else {
            Log.i(TAG,"rpdu " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return null;
        }
    }

    /**
     * connect (START) to SAM
     * @return
     */
    public boolean connectCard() {
        return true;
    }

    public boolean disconnectCard() {
        BasicOper.dc_cpudown();
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
        Log.i(TAG, "connectSAM: psamSlot = " + psamSlot);

        BasicOper.dc_setcpu(psamSlot);
       // BasicOper.dc_beep(10);
        String[] resultArr;
        resultArr = BasicOper.dc_cpureset_hex().split("\\|", -1);
        if (resultArr[0].equals("0000")) {
            Log.i(TAG,"dc_cpureset_hex success," + "ATR/ATS = " + resultArr[1]);
            return resultArr[1].getBytes();
        } else {
            Log.i(TAG,"dc_cpureset_hex " + "error code = " + resultArr[0] + " error msg = " + resultArr[1]);
            return null;
        }
    }



}
