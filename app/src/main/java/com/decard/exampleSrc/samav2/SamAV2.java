/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.decard.exampleSrc.samav2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**

 @author duma
 */
public class SamAV2 implements ISamService {

    private ISamAv2IO samChannel;

    private static SamAV2 uniqueInstance = null;
    private boolean deviceInstanced = false;

    public SamAV2(ISamAv2IO samDevice) {
        samChannel = samDevice;
    }

    public boolean disconnectSAM()  {
        samChannel.disconnectCard();
        return true;
    }

    //<editor-fold defaultstate="collapsed" desc="SAM-AV2">
    /**
     Obtiene los bytes de la respuesta ATR de la SAM

     @return
     */
    public byte[] connectSAM()  {

//        if (samChannel.getTerminal().isCardPresent())
        samChannel.connectCard();
//        else
//            return null;

        byte[] output = samChannel.getATR();

        return output;
    }

    /**
     Preparar la SAM para realizar funciones de criptograficas con la llave
     noKey

     @param noKey

     @return
     */
    public boolean samAV2_ActivateOfflineKey(int noKey)  {

        byte[] apdu = new byte[]{(byte) 0x80, (byte) 0x01, 0x00, 0x00, 0x02,
            (byte) noKey, 0x00};

        byte[] response = samChannel.sendApduCommand(apdu);

//        Log.i(TAG, "SAlida de ActivateOfflineKey, resp: [ " + ByteArrayTools.byteArrayToHexString(response) + "]");
        return verificarRespuestaCorrecta(response);

    }

    /**
     Cifrar los datos de entrada 'data' con la llave activa en pasos
     anetriores (ActivateOfflineKey)

     @param data

     @return
     */
    public byte[] samAV2_EncipherData(byte[] data)  {

        byte[] apdu1 = new byte[]{(byte) 0x80, (byte) 0xED, 0x00, 0x00, (byte) data.length};
        //0x80ED0000LeDa00

        ArrayList<byte[]> tempA = new ArrayList<byte[]>();

        tempA.add(apdu1);
        tempA.add(data);
        tempA.add(new byte[]{0x00});

        byte[] apdu = ByteArrayTools.flatten(tempA);

        byte[] response = samChannel.sendApduCommand(apdu);
//        Log.i(TAG, "SAlida de EncipherData, resp: [ " + ByteArrayTools.byteArrayToHexString(response) + "]");

        if ( verificarRespuestaCorrecta(response) ) {
            return Arrays.copyOf(response, response.length - 2);
        } else {
            return null;
        }

    }

    /**
     Autenticaci�n mutua (host/SAM) entre la aplicaci�n y la samAv2 usando la
     llave n�mero 'noKey'

     @param key
     @param noKey

     @return
     */
    public boolean samAV2_authHost(byte[] key, int keyNumber)  {

        byte[] iv = new byte[16];
        for ( int i = 0; i < iv.length; i++ ) {
            iv[i] = (byte) 0x00;

        }

        CipherAES funcionCipher1 = new CipherAES(key);

        byte[] apdu = new byte[]{(byte) 0x80, (byte) 0xA4, 0x00, 0x00, 0x03,
            (byte) keyNumber, 0x00, 0x00, 0x00};

        byte[] response = samChannel.sendApduCommand(apdu);

        if ( response == null ) {
            return false;
        }

        if ( response[response.length - 1] != (byte) 0xAF ) {
            return false;
        }

        byte[] rnd2 = Arrays.copyOfRange(response, 0, response.length - 2);
//        byte [] rnd2 = new byte [] {0x23, 0x4b, (byte)0x8c, 0x14, 0x77, 0x3f,
//            0x34, 0x36, 0x1a, 0x2d, (byte)0xed, (byte)0xa1};

        byte[] variableTemp1 = new byte[rnd2.length + 4];
        System.arraycopy(rnd2, 0, variableTemp1, 0, rnd2.length);

        for ( int i = variableTemp1.length - 4; i < variableTemp1.length - 1; i++ ) {
            variableTemp1[i] = 0x00;
        }

//        Log.i(TAG, "response: [ " + ByteArrayTools.byteArrayToHexString(response) + " ]");
//
//        Log.i(TAG, "rnd2: [ " + ByteArrayTools.byteArrayToHexString(rnd2) + " ]");
//        Log.i(TAG, "var1: [ " + ByteArrayTools.byteArrayToHexString(variableTemp1) + " ]");
        byte[] cmac = funcionCipher1.hashCMAC(variableTemp1);

        byte[] rnd1 = new byte[rnd2.length];

//        byte [] rnd1 = new byte [] {0x66,(byte)0xa0,0x04,0x2a,(byte)0xd5,
//            (byte)0xfe,(byte)0xee,(byte)0xb9,0x2f,(byte)0x28,(byte)0xa0,0x74};
        new Random().nextBytes(rnd1);

        byte[] apdu2 = new byte[rnd1.length + cmac.length + 6];

        apdu2[0] = (byte) 0x80;
        apdu2[1] = (byte) 0xA4;
        apdu2[2] = (byte) 0x00;
        apdu2[3] = (byte) 0x00;
        apdu2[4] = (byte) 0x14;
        apdu2[apdu2.length - 1] = 0x00;

        System.arraycopy(cmac, 0, apdu2, 5, cmac.length);
        System.arraycopy(rnd1, 0, apdu2, 5 + cmac.length, rnd1.length);

        byte[] response2 = samChannel.sendApduCommand(apdu2);

//        long t1 = System.currentTimeMillis();
        if ( response2 == null ) {
            return false;
        }

        if ( response2[response2.length - 1] != (byte) 0xAF ) {
            return false;
        }

        byte[] rndBC = Arrays.copyOfRange(response2, 8, response2.length - 2);
//        byte [] rndBC = {0x62,0x39,(byte)0x95,(byte)0xc6,(byte)0x9b,(byte)0xf9,
//            (byte)0xd5,0x39,(byte)0xb3,0x2f,(byte)0xa7,0x62,0x52,0x50,0x7e,0x45};

//        Log.i(TAG, "rndBC: [ " + ByteArrayTools.byteArrayToHexString(rndBC) + " ]");
        byte[] divkey = CipherUtils.divKey(rnd1, rnd2);

        funcionCipher1.setIvBytes(iv);

        byte[] kex = funcionCipher1.encrypt(divkey);

//        Log.i(TAG, "kex: [ " + ByteArrayTools.byteArrayToHexString(kex) + " ]");
        CipherAES funcionCipher2 = new CipherAES(kex);

        funcionCipher2.setIvBytes(iv);

        byte[] rndB = funcionCipher2.decrypt(rndBC);

//        Log.i(TAG, "rndB: [ " + ByteArrayTools.byteArrayToHexString(rndB) + " ]");
        byte[] rndA = new byte[rndB.length];

        new Random().nextBytes(rndA);

        byte[] rndBP = CipherUtils.rotateArray(rndB, 2);

        byte[] contRND = new byte[rndA.length + rndBP.length];

        System.arraycopy(rndA, 0, contRND, 0, rndA.length);
        System.arraycopy(rndBP, 0, contRND, rndA.length, rndBP.length);

        funcionCipher2.setIvBytes(iv);

        byte[] ecipher = funcionCipher2.encrypt(contRND);

        byte[] apdu3 = new byte[ecipher.length + 6];

        apdu3[0] = (byte) 0x80;
        apdu3[1] = (byte) 0xA4;
        apdu3[2] = (byte) 0x00;
        apdu3[3] = (byte) 0x00;
        apdu3[4] = (byte) 0x20;
        apdu3[apdu3.length - 1] = (byte) 0x00;

        System.arraycopy(ecipher, 0, apdu3, 5, ecipher.length);

        byte[] response3 = samChannel.sendApduCommand(apdu3);

        if ( !verificarRespuestaCorrecta(response3) ) {
            return false;
        }

        funcionCipher2.setIvBytes(iv);
        byte[] rndAP = funcionCipher2.decrypt(Arrays.copyOfRange(response3, 0, response3.length - 2));

        byte[] rndAP_real = CipherUtils.rotateArray(rndA, 2);

        boolean result = true;

        for ( int i = 0; i < rndAP_real.length; i++ ) {
            if ( rndAP_real[i] != rndAP[i] ) {
                result = false;
                break;
            }
        }

        return result;
    }

    /**
     Obtener la llave diversificada civica (3DES) a partir de dato
     diversificado 'numeroUnicoTarjetaByteArray' y el identificador de la
     llave samAv2 que se usar�

     @param keyIdentifier
     @param numeroUnicoTarjetaByteArray

     @return
     @throws Exception
     */
    public byte[] samAV2_llaveDiv(byte keyIdentifier, byte[] numeroUnicoTarjetaByteArray) throws Exception {

//        Log.i(TAG, "data para la diversificacion: [ " + ByteArrayTools.byteArrayToHexString(numeroUnicoTarjetaByteArray) + "]");
        if ( !samAV2_ActivateOfflineKey(keyIdentifier) ) {
            return null;
        }

        byte[] response = samAV2_EncipherData(numeroUnicoTarjetaByteArray);

        if ( response == null ) {
            return null;
        }

        return response;
    }

    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="SamAV2-MifarePLUS">
    /**
     Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     trav�s del comando Read. Este metodo solo lee en modo plano, para
     habilitar la lectura en modo cifrado ser� necesario modificar el metodo

     @param bloq posici�n en la trajeta del bloque de datos a leer
     @param len  longitud de bloques a leer

     @return
     @throws Exception
     */
    @Override
    public byte[] samAV2_combinedReadMFP(byte cmd[], byte[] dataResp) throws Exception {

        byte[] apdu;

        int p1 = 0;

        if ( dataResp != null ) {
            p1 = 0x10;
        }

        if ( dataResp != null ) {
            p1 = 2;
            apdu = new byte[cmd.length + dataResp.length + 6];
            apdu[4] = (byte) ( cmd.length + dataResp.length );

            System.arraycopy(cmd, 0, apdu, 5, 4);
            System.arraycopy(dataResp, 0, apdu, 9, dataResp.length);
        } else {

            apdu = new byte[cmd.length + 6];
            System.arraycopy(cmd, 0, apdu, 5, 4);
            apdu[4] = (byte) ( cmd.length );
        }

        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0x33;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) 0x00;

        apdu[apdu.length - 1] = 0x00;

        byte[] response = samChannel.sendApduCommand(apdu);

        if ( verificarRespuestaCorrecta(response) ) {
            return Arrays.copyOf(response, response.length - 2);
        } else {
            return null;
        }

    }

    /**
     Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     trav�s del comando Write (write, decrement, increment, transfer).

     @param data

     @return
     @throws Exception
     */
    @Override
    public byte[] samAV2_combinedWriteMFP(byte[] data) throws Exception {

////
//        if (!persistentAUTH_next) {
////            this.mplus_resetAuth();
//            byte [] auth1 = this.mplus_firstAuth_f1(0x4000);
//            byte [] auth2 = this.samAV2_authMFP_f1(true, 3, 0x01, 0x00, auth1, null);
//            byte [] auth3 = this.mplus_nextAuth_f2(auth2);
//
//            persistentAUTH_next = this.samAV2_authMFP_f2(auth3);
////            persistentAUTH_next = true;
//
//        }
        byte[] apdu = new byte[data.length + 6];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0x34;
        apdu[2] = (byte) 0x00;
        apdu[3] = (byte) 0x00;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        apdu[apdu.length - 1] = 0x00;

        byte[] response = samChannel.sendApduCommand(apdu);

        if ( verificarRespuestaCorrecta(response) ) {
            return Arrays.copyOf(response, response.length - 2);
        } else {
            return null;
        }

    }

    @Override
    public byte[] samAV2_plainReadMFP(int bloq, int len) throws Exception {

        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[4];
        apdu[0] = (byte) 0x36;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = (byte) len;

        byte[] response = this.samAV2_combinedReadMFP(apdu, null);

        if ( response == null ) {
            return null;
        }

        return response;

    }

    @Override
    public byte[] samAV2_plainWriteMFP(int bloq, byte[] data) throws Exception {

        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 3];
        apdu[0] = (byte) 0xA2;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        System.arraycopy(data, 0, apdu, 3, data.length);

        byte[] response = this.samAV2_combinedWriteMFP(apdu);

        if ( response == null ) {
            return null;
        }

        return response;

    }

    private byte[] samAV2_cipherWriteMFP(int bloq, byte[] data) throws Exception {

        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[data.length + 3];
        apdu[0] = (byte) 0xA0;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        System.arraycopy(data, 0, apdu, 3, data.length);

        byte[] response = this.samAV2_combinedWriteMFP(apdu);

        if ( response == null ) {
            return null;
        }

        return response;

    }

    private byte[] samAV2_incrTransMFP(int bloq, int value) throws Exception {

        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[9];
        apdu[0] = (byte) 0xB0;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = bloque2;
        apdu[4] = bloque1;
        apdu[5] = (byte) ( ( value ) & 0xFF );
        apdu[6] = (byte) ( ( value >> 8 ) & 0xFF );
        apdu[7] = (byte) ( ( value >> 16 ) & 0xFF );
        apdu[8] = (byte) ( ( value >> 24 ) & 0xFF );

        byte[] response = this.samAV2_combinedWriteMFP(apdu);

        if ( response == null ) {
            return null;
        }

        return response;

    }

    @Override
    public byte[] samAV2_decrTransMFP(int bloq, int value) throws Exception {

        byte bloque1 = (byte) ( ( bloq >> 8 ) & 0xFF );
        byte bloque2 = (byte) ( ( bloq ) & 0xFF );

        byte[] apdu = new byte[9];
        apdu[0] = (byte) 0xB8;
        apdu[1] = bloque2;
        apdu[2] = bloque1;
        apdu[3] = bloque2;
        apdu[4] = bloque1;
        apdu[5] = (byte) ( ( value ) & 0xFF );
        apdu[6] = (byte) ( ( value >> 8 ) & 0xFF );
        apdu[7] = (byte) ( ( value >> 16 ) & 0xFF );
        apdu[8] = (byte) ( ( value >> 24 ) & 0xFF );

        byte[] response = this.samAV2_combinedWriteMFP(apdu);

        if ( response == null ) {
            return null;
        }

        return response;

    }

    /**
     Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     trav�s del comando Auth.

     @param firtsAuth
     @param level
     @param key_no
     @param key_ver
     @param data
     @param data_div

     @return
     @throws Exception
     */
    @Override
    public byte[] samAV2_authMFP_f1(boolean firtsAuth, int level, int key_no, int key_ver, byte[] data, byte[] data_div) throws Exception {

        if ( data == null ) {
            return null;
        }

        byte[] apdu;
        byte p1 = 0x00;
        if ( ( data_div == null ) ) {
            p1 = 0x00;
        } else {
            p1 = 0x01;
        }

        if ( !( firtsAuth ) ) {
            p1 = (byte) ( p1 | 0x02 );
        }

        switch ( level ) {
            case 1:
                p1 = (byte) ( p1 | 0x00 );
                break;
            case 2:
                p1 = (byte) ( p1 | 0x04 );
                break;
            case 3:
                p1 = (byte) ( p1 | 0x0C );
                break;
            default:
                p1 = (byte) ( p1 | 0x0A );
                break;
        }

        if ( data_div == null ) {
            apdu = new byte[data.length + 8];
            apdu[0] = (byte) 0x80;
            apdu[1] = (byte) 0xA3;
            apdu[2] = p1;
            apdu[3] = 0x00;
            apdu[4] = (byte) ( data.length + 2 );
            apdu[5] = (byte) key_no;
            apdu[6] = (byte) key_ver;
            System.arraycopy(data, 0, apdu, 7, data.length);
            apdu[apdu.length - 1] = 0x00;
        } else {
            apdu = new byte[data.length + data_div.length + 8];
            apdu[0] = (byte) 0x80;
            apdu[1] = (byte) 0xA3;
            apdu[2] = p1;
            apdu[3] = 0x00;
            apdu[4] = (byte) ( data.length + data_div.length + 2 );
            apdu[5] = (byte) key_no;
            apdu[6] = (byte) key_ver;
            System.arraycopy(data, 0, apdu, 7, data.length);
            System.arraycopy(data_div, 0, apdu, 7 + data.length, data_div.length);
            apdu[apdu.length - 1] = 0x00;
        }

        byte[] response = samChannel.sendApduCommand(apdu);

        if ( response != null && ( ( response[response.length - 2] == (byte) 0x90 && response[response.length - 1] == (byte) 0xAF ) ) ) {
            return Arrays.copyOf(response, response.length - 2);
        } else {
            return null;
        }

    }

    @Override
    public boolean samAV2_authMFP_f2(byte[] data) throws Exception {

        if (data == null) {
            samChannel.sendApduCommand(new byte[]{(byte)0x80,(byte)0xCA,0x01,0x00});
            return false;
        }

        byte[] apdu = new byte[data.length + 6];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xA3;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        apdu[apdu.length - 1] = 0x00;
        byte[] response = samChannel.sendApduCommand(apdu);
        return ( verificarRespuestaCorrecta(response) );

    }

    /**
     Verifica que la respuesta retornada por el dispositivo sea que ejecuto la
     funcion de forma correcta, no quiere decir que la funcion realizo la
     tarea exitosa, solo que el lector entendio la funcion y la invoco con
     exito sin iomportar el resultado de la funcion

     @param response

     @return True en caso que se halla invokado la funcion
     */
    public boolean verificarRespuestaCorrecta(byte[] response) {
        //verifico que el final de la trama sea 90 00
        if ( response != null && ( ( response[response.length - 2] == (byte) 0x90 && response[response.length - 1] == (byte) 0x00 ) ) ) {
            return true;
        }

        return false;
    }

}
