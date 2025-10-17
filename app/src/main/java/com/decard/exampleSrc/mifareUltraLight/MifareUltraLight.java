/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.decard.exampleSrc.mifareUltraLight;
import android.annotation.SuppressLint;
import android.util.Log;

import com.decard.exampleSrc.desfire.ev1.model.command.Utils;
import com.decard.exampleSrc.mifarePlus.IMifarePlusIO;


import java.util.Arrays;

/**

 @author ben
 */
public class MifareUltraLight {

    private IMifarePlusIO mplusMgr;

	public static final byte MFUL_RESP_ACK = (byte)0x0A;   /**< MIFARE Ultralight ACK response code */
	public static final byte MFUL_RESP_NAK0 = (byte)0x00;   /**< MIFARE Ultralight NAK0 response code */
	public static final byte MFUL_RESP_NAK1 = (byte)0x01;   /**< MIFARE Ultralight NAK1 response code */
	public static final byte MFUL_RESP_NAK4 = (byte)0x04;   /**< MIFARE Ultralight NAK4 response code */
	public static final byte MFUL_RESP_NAK5 = (byte)0x05;   /**< MIFARE Ultralight NAK5 response code */

	public static final byte MFUL_CMD_READ = (byte)0x30;   /**< MIFARE Ultralight Read command byte */
	public static final byte MFUL_CMD_COMPWRITE = (byte)0xA0;   /**< MIFARE Ultralight Compatibility Write command byte */
	public static final byte MFUL_CMD_WRITE = (byte)0xA2;   /**< MIFARE Ultralight Write command byte */
	public static final byte MFUL_CMD_AUTH = (byte)0x1A;   /**< MIFARE Ultralight Authenticate command byte */
	public static final byte MFUL_CMD_INCR_CNT = (byte)0xA5;   /**< MIFARE Ultralight Increment count command byte */
	public static final byte MFUL_CMD_READ_CNT = (byte)0x39;   /**< MIFARE Ultralight Read counter command byte */
	public static final byte MFUL_CMD_PWD_AUTH = (byte)0x1B;   /**< MIFARE Ultralight Password Auth command byte */
	public static final byte MFUL_CMD_GET_VER = (byte)0x60;   /**< MIFARE Ultralight Get version command byte */
	public static final byte MFUL_CMD_FAST_READ = (byte)0x3A;   /**< MIFARE Ultralight Fast read command byte */
	public static final byte MFUL_CMD_READ_SIG = (byte)0x3C;   /**< MIFARE Ultralight Read signature command byte */
	public static final byte MFUL_CMD_CHK_TRG_EVT = (byte)0x3E;   /**< MIFARE Ultralight Check tearing event command byte */
	public static final byte MFUL_CMD_SECTOR_SELECT = (byte)0xC2;   /**< Type 2 tag sector select command byte */

	public static final byte MFUL_PREAMBLE_TX = (byte)0xAF;   /**< MIFARE Ultralight preamble byte (tx) for authentication. */
	public static final byte MFUL_PREAMBLE_RX = (byte)0x00;   /**< MIFARE Ultralight preamble byte (rx) for authentication. */

	public static final int MFUL_COMPWRITE_BLOCK_LENGTH = 16; /**< Length of a compatibility write MIFARE(R) Ultralight data block. */

	private static final int MFUL_WRITE_BLOCK_LENGTH = 4;
	private static final int MFUL_COUNTER_WR_VALUE_LENGTH = 4;
	private static final int MFUL_VERSION_LENGTH = 8;
	private static final int MFUL_PACK_LENGTH = 2;
	private static final int MFUL_COUNTER_RD_VALUE_LENGTH = 3;

	public static final byte NTAG21X_COMMAND_GET_VERSION = (byte)0x60;           /**< get version command */
	public static final byte  NTAG21X_COMMAND_READ = (byte)0x30;           /**< read command */
	public static final byte NTAG21X_COMMAND_FAST_READ = (byte)0x3A;           /**< fast read command */
	public static final byte NTAG21X_COMMAND_WRITE = (byte)0xA2;           /**< write command */
	public static final byte NTAG21X_COMMAND_COMP_WRITE = (byte)0xA0;           /**< comp write command */
	public static final byte NTAG21X_COMMAND_READ_CNT = (byte)0x39;           /**< read cnt command */
	public static final byte NTAG21X_COMMAND_PWD_AUTH = (byte)0x1B;           /**< pwd auth command */
	public static final byte NTAG21X_COMMAND_READ_SIG = (byte)0x3C;           /**< read sig command */

    public MifareUltraLight(IMifarePlusIO mplusChannel) {
        mplusMgr = mplusChannel;
    }


	public byte[] mful_Read(byte bAddress){

        byte[] apdu = new byte[2];

        apdu[0] = MFUL_CMD_READ;
        apdu[1] = bAddress;

        return sendApduCommand(apdu);
	}
	public boolean mful_SectorSelect(byte bSecNo ){

        byte[] apdu = new byte[2];

        apdu[0] = MFUL_CMD_SECTOR_SELECT;
        apdu[1] = bSecNo;

		byte[] response = sendApduCommand(apdu);

		return (response != null);
	}
	//
	public boolean mful_Write(byte bAddress,byte[] pData){
		if(pData == null)
			return false;
        byte[] apdu = new byte[2 + pData.length];
        apdu[0] = MFUL_CMD_WRITE;
        apdu[1] = bAddress;
        System.arraycopy(pData, 0, apdu, 2, pData.length);
        byte[] response = sendApduCommand(apdu);

		return (response != null);
    }
	public boolean mful_CompatibilityWrite(byte bAddress,byte[] pData){
		

        byte[] apdu = new byte[2 + MFUL_COMPWRITE_BLOCK_LENGTH];
		if((pData == null) || (pData.length != MFUL_COMPWRITE_BLOCK_LENGTH))
			return false;

        apdu[0] = MFUL_CMD_COMPWRITE;
        apdu[1] = bAddress;
		System.arraycopy(pData, 0, apdu, 0, pData.length);

		byte[] response = sendApduCommand(apdu);

		return (response != null);
	}

	public boolean mful_IncrCnt(byte bCntNum, byte[] pCnt ){
		
        byte[] apdu = new byte[2 + MFUL_COUNTER_WR_VALUE_LENGTH];
		if((pCnt == null) || (pCnt.length != MFUL_COUNTER_WR_VALUE_LENGTH)) {
			return false;
		}
        apdu[0] = MFUL_CMD_INCR_CNT;
        apdu[1] = bCntNum;
        System.arraycopy(pCnt, 0, apdu, 0, pCnt.length);

        byte[] response = sendApduCommand(apdu);
		
		return (response != null);
	}


	public byte[] mful_ReadCnt(byte bCntNum){
        byte[] apdu = new byte[2];
        apdu[0] = MFUL_CMD_READ_CNT;
        apdu[1] = bCntNum;

        byte[] response = sendApduCommand(apdu);
		
		if((response == null) || (response.length != MFUL_COUNTER_RD_VALUE_LENGTH)){
			return null;
		}
		return response;
	}

	public boolean mful_PwdAuth(byte[] pPwd,byte[] pack){
	
        byte[] apdu = new byte[1 + MFUL_WRITE_BLOCK_LENGTH];
		if((pPwd == null) ||
				(pPwd.length != MFUL_WRITE_BLOCK_LENGTH) ||
				(pack == null) ||
				(pack.length < 2)) {
			return false;
		}
        apdu[0] = MFUL_CMD_PWD_AUTH;
		System.arraycopy(pPwd, 0, apdu, 1, pPwd.length);
		
        byte[] response = sendApduCommand(apdu);
		
		if((response == null) || (response.length != MFUL_PACK_LENGTH)){
			return false;
		}

		return Arrays.equals(response,pack);
	}
	public void test_crc16(){
		byte[] cmd1 = new byte[]{0x60};
		byte[] cmd2 = new byte[]{0x30,0x00 };
		byte[] cmd3 = new byte[]{0x3C,0x00 };
		byte[] cmd4 = new byte[]{0x30,0x03 };
		byte[] cmd5 = new byte[]{0x3A,0x03,0x05 };
		byte[] cmd6 = new byte[]{(byte)0xA2,(byte)0x85,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF };
		byte[] cmd7 = new byte[]{(byte)0xA2,(byte)0x86,0x00,0x00,0x00,0x00 };
		byte[] cmd8 = new byte[]{0x1B,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
		byte[] crc = Utils.crc16(cmd1);
		Log.i("crc16 ", Utils.getHexString(cmd1) + " crc:" + Utils.getHexString(crc));

		crc = Utils.crc16(cmd2);
		Log.i("crc16 ", Utils.getHexString(cmd2) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd3);
		Log.i("crc16 ", Utils.getHexString(cmd3) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd4);
		Log.i("crc16 ", Utils.getHexString(cmd4) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd5);
		Log.i("crc16 ", Utils.getHexString(cmd5) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd6);
		Log.i("crc16 ", Utils.getHexString(cmd6) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd7);
		Log.i("crc16 ", Utils.getHexString(cmd7) + " crc:" + Utils.getHexString(crc));
		crc = Utils.crc16(cmd8);
		Log.i("crc16 ", Utils.getHexString(cmd8) + " crc:" + Utils.getHexString(crc));
		/*
		crc:f8 32
		crc:02 a8
		crc:a2 01
		crc:99 9a
		crc:05 2d
		crc:bf e0
		crc:ea 0e
		crc:63 00
		*/
	}
	public byte[] sendApduCommand(byte[] _apdu){
		/*
		byte[] apdu =  new byte[_apdu.length + 2];
		byte[] crc = Utils.crc16(_apdu);
		//test_crc16();
		System.arraycopy(_apdu, 0, apdu, 0, _apdu.length);
		System.arraycopy(crc, 0, apdu, _apdu.length, 2);
		byte[] _response = mplusMgr.sendApduCommand(apdu);
		*/
		byte[] _response = mplusMgr.sendApduCommand(_apdu);

		return _response;
	}
	public byte[] mful_GetVersion(){
		
        byte[] apdu = new byte[1];

        apdu[0] = MFUL_CMD_GET_VER;

        return sendApduCommand(apdu);
	}
	public byte[] mful_FastRead(byte bStartAddr, byte bEndAddr){
        byte[] apdu = new byte[3];
		int bytesRead = ((bEndAddr - bStartAddr + 1) * 4);
		if(bytesRead < 0) {
			return null;
		}
        apdu[0] = MFUL_CMD_FAST_READ;
        apdu[1] = bStartAddr;
        apdu[2] = bEndAddr;

        byte[] response = sendApduCommand(apdu);

		if((response == null) || (response.length != bytesRead)){
			return null;
		}
		return response;
	}


	public byte[] mful_ReadSign(byte bAddr){

        byte[] apdu = new byte[2];

        apdu[0] = MFUL_CMD_READ_SIG;
        apdu[1] = bAddr;

        return sendApduCommand(apdu);
	}


	public byte phalMful_ChkTearingEvent(byte bCntNum){
		
        byte[] apdu = new byte[2];

        apdu[0] = MFUL_CMD_CHK_TRG_EVT;
        apdu[1] = bCntNum;
        byte[] response = sendApduCommand(apdu);
		if((response == null) || (response.length != 1)){
			return 0x00;
		}
		return response[0];
	}

}
