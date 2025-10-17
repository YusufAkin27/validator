/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.samav2;

import java.nio.ByteBuffer;

/**
 *
 * @author cfsolano
 */
public class IntArrayTools {

    /**
     * Concatena los enteros dentro de un array en un entero
     *
     * @param arr
     * @return un entero formado concatenando cada valor dentro del array
     */
    public static int intArrayToInt(int[] arr) {
        int j = 1;
        int res = 0;
        for (int i = arr.length - 1; i >= 0; i--, j = j * 10) {
            res += arr[i] * j;
        }
        return res;
    }

    public static int intArrayToStrign(int[] arr) {
        int j = 1;
        int res = 0;
        for (int i = arr.length - 1; i >= 0; i--, j = j * 10) {
            res += arr[i] * j;
        }
        return res;
    }

    public static void main(String... arg) {
        int[] arr = {1, 2, 3, 4};
        int res = intArrayToInt(arr);
        System.out.println(res);
    }

    public static int[] byteArrayToIntArray(byte[] ba) {
        int[] res = new int[ba.length];
        for (int i = 0; i < ba.length; i++) {
            res[i] = ba[i];
        }
        return res;
    }

    public static byte[] intArrayToByteArray(int[] ba) {
        byte[] res = new byte[ba.length];
        for (int i = 0; i < ba.length; i++) {
            res[i] = (byte) ba[i];
        }
        return res;
    }

    public static int byteArrayToInt(byte[] array) {
        return ByteBuffer.wrap(array).getInt();
    }
}
