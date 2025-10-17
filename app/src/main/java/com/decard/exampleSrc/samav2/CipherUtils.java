/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.decard.exampleSrc.samav2;


/**
 *
 * @author duma
 */
public class CipherUtils {

    
    public static byte [] divKey(byte []  rnd1, byte [] rnd2){
        
        byte [] a_xor = new byte[5];
        
        for (int i = 0; i < a_xor.length; i++) {
            a_xor[i] = (byte)(rnd1[i] ^ rnd2[i]);            
        }
        
        byte [] res = new byte [16];
        
        System.arraycopy(rnd1, 7, res, 0, 5);
        System.arraycopy(rnd2, 7, res, 5, 5);
        System.arraycopy(a_xor, 0, res, 10, 5);
        res[res.length-1] = (byte)0x91;
        
//        Log.i(TAG, "res divKey: [ " + ByteArrayTools.byteArrayToHexString(res) + " ]");
        return res;
    }
    
    public static byte [] rotateArray(byte[] array, int index)
    {
        byte[] result;

        result = new byte[array.length];

        System.arraycopy(array, index, result, 0, array.length - index);
        System.arraycopy(array, 0, result, array.length - index, index);
        
//        Log.i(TAG, "sin rot: [ " + ByteArrayTools.byteArrayToHexString(array) + " ]");
//        Log.i(TAG, "con rot: [ " + ByteArrayTools.byteArrayToHexString(result) + " ]");

        //System.arraycopy(result, 0, array, 0, array.length);
        
        return result;
    }
    
}
