/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.decard.exampleSrc.mifarePlus;


import java.util.Arrays;

/**

 @author duma
 */
public class MifarePlus {

    private IMifarePlusIO mplusMgr;



    public MifarePlus(IMifarePlusIO mplusChannel) {
        mplusMgr = mplusChannel;
    }

    private byte[] mplus_read(int bloq, int len, byte[] cmac) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[cmac.length + 4];

        apdu[0] = 0x32;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = (byte) len;
        System.arraycopy(cmac, 0, apdu, 4, cmac.length);

        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response != null && ( response[0] == (byte) 0x90 ) ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
        }
    }
    public int mplus_AuthKey(int keyBNr, byte[] authKey){

        byte[] apdu = new byte[4];

        apdu[0] = 0x70;
        apdu[1] = (byte)(keyBNr % 256);
        apdu[2] = (byte)(keyBNr / 256);
        apdu[3] = (byte) 00;
        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response != null  ) {
            return 0;
        } else {
            return -1;
        }

    }
    public byte[] mplus_plainRead(int bloq, int len) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[4];

        apdu[0] = 0x36;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = (byte) len;

        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response != null && ( response[0] == (byte) 0x90 ) ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
        }

    }

    public boolean mplus_plainWrite(int bloq, byte[] data) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 3];

        apdu[0] = (byte) 0xA2;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        System.arraycopy(data, 0, apdu, 3, data.length);

        byte[] response = mplusMgr.sendApduCommand(apdu);
        if ( response == null ) {
            return false;
        }

        return response[0] == (byte) 0x90;
    }

    public boolean mplus_cipherWrite(int bloq, byte[] data) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 3];

        apdu[0] = (byte) 0xA0;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        System.arraycopy(data, 0, apdu, 3, data.length);

        byte[] response = mplusMgr.sendApduCommand(apdu);
        if ( response == null ) {
            return false;
        }

        return response[0] == (byte) 0x90;
    }

    public boolean mplus_incrTrans(int bloq, byte[] data) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 5];

        apdu[0] = (byte) 0xB6;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = bloque2;
        apdu[4] = bloque1;
        System.arraycopy(data, 0, apdu, 5, data.length);

        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response == null ) {
            return false;
        }

        return response[0] == (byte) 0x90;
    }

    public boolean mplus_decrTrans(int bloq, byte[] data) throws Exception {
        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 5];

        apdu[0] = (byte) 0xB8;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = bloque2;
        apdu[4] = bloque1;
        System.arraycopy(data, 0, apdu, 5, data.length);

        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response == null ) {
            return false;
        }

        return response[0] == (byte) 0x90;
    }

    public byte[] mplus_firstAuth_f1(int key) throws Exception {
        byte bloque1 = (byte) ( ( key >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( key ) & 0xFF );

        byte[] apdu = new byte[4];

        apdu[0] = 0x70;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = 0x00;

        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response == null ) {
            return null;
        }

        if ( response[0] == (byte) 0x90 ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
//            return new byte[]{response[0]};
        }
    }

    public byte[] mplus_firstAuth_f1_cc(int key) throws Exception {
        byte bloque1 = (byte) ( ( key >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( key ) & 0xFF );

        byte[] apdu = new byte[4];

        apdu[0] = 0x70;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = 0x00;
        byte[] response = mplusMgr.sendApduControlCommand(apdu);

        if ( response == null ) {
            return null;
        }

        if ( response[0] == (byte) 0x90 ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
//            return new byte[]{response[0]};
        }
    }

    public byte[] mplus_firstAuth_f2(byte[] data) throws Exception {
        if ( data == null ) {
            return null;
        }

        byte[] apdu = new byte[data.length + 1];

        apdu[0] = (byte) 0x72;
        System.arraycopy(data, 0, apdu, 1, data.length);
        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response == null ) {
            return null;
        }

        if ( response[0] == (byte) 0x90 ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
//            return new byte[]{response[0]};
        }
    }

    public byte[] mplus_firstAuth_f2_cc(byte[] data) throws Exception {
        if ( data == null ) {
            return null;
        }

        byte[] apdu = new byte[data.length + 1];

        apdu[0] = (byte) 0x72;
        System.arraycopy(data, 0, apdu, 1, data.length);
        byte[] response = mplusMgr.sendApduControlCommand(apdu);

        if ( response == null ) {
            return null;
        }

        if ( response[0] == (byte) 0x90 || response[1] == (byte) 0x90 ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
//            return new byte[]{response[0]};
        }
    }

//    private boolean mplus_firstAuth_f2(byte [] data) throws Exception {
//
//        byte [] apdu = new byte [data.length +1];
//
//        apdu[0] = (byte) 0x72;
//        System.arraycopy(data, 0, apdu, 1, data.length);
//        byte [] response = mplusMgr.sendApduCommand(apdu);
//
//        return response[0] == (byte)0x90;
//
//    }
    public byte[] mplus_nextAuth_f1(int key) throws Exception {
        byte bloque1 = (byte) ( ( key >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( key ) & 0xFF );

        byte[] apdu = new byte[3];

        apdu[0] = 0x76;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response != null && ( response[0] == (byte) 0x90 ) ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
        }
    }

    public byte[] mplus_nextAuth_f2(byte[] data) throws Exception {

        byte[] apdu = new byte[data.length + 1];

        apdu[0] = (byte) 0x72;
        System.arraycopy(data, 0, apdu, 1, data.length);
        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response != null && ( response[0] == (byte) 0x90 ) ) {
            return Arrays.copyOfRange(response, 1, response.length);
        } else {
            return null;
        }
    }

    public boolean mplus_resetAuth() throws Exception {

        byte[] apdu = new byte[1];

        apdu[0] = (byte) 0x78;
        byte[] response = mplusMgr.sendApduCommand(apdu);

        if ( response == null ) {
            return false;
        }

        return response[0] == (byte) 0x90;
    }

}
