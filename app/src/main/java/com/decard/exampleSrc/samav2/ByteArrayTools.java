/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.samav2;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author INDRA Sistemas
 */
public class ByteArrayTools {

    private static final char[] HEX_DIGITS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static final char[] HEX_LOWER_CASE_DIGITS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    public static byte[] intToByteArray(int value) {
        return new byte[]{
                    (byte) (value >>> 24),
                    (byte) (value >>> 16),
                    (byte) (value >>> 8),
                    (byte) value};
    }

    public static byte[] toByteArray(byte b) {
        byte[] array = new byte[]{b};
        return array;
    }

    public static byte[] toByteArray(int i) {
        byte[] array = new byte[]{(byte)(i >> 24 & 255), (byte)(i >> 16 & 255), (byte)(i >> 8 & 255), (byte)(i & 255)};
        return array;
    }

    private static int toByte(char c) {
        if (c >= '0' && c <= '9') {
            return c - 48;
        } else if (c >= 'A' && c <= 'F') {
            return c - 65 + 10;
        } else if (c >= 'a' && c <= 'f') {
            return c - 97 + 10;
        } else {
            throw new RuntimeException("Invalid hex char '" + c + "'");
        }
    }
    public static String toHexString(byte b) {
        return toHexString(toByteArray(b));
    }

    public static String toHexString(byte[] array) {
        if(array == null || array.length == 0)
            return "";
        return toHexString(array, 0, array.length, true);
    }

    public static String toHexString(byte[] array, boolean upperCase) {
        if(array == null || array.length == 0)
            return "";
        return toHexString(array, 0, array.length, upperCase);
    }

    public static String toHexString(byte[] array, int offset, int length) {
        return toHexString(array, offset, length, true);
    }

    public static String toHexString(byte[] array, int offset, int length, boolean upperCase) {
        char[] digits = upperCase ? HEX_DIGITS : HEX_LOWER_CASE_DIGITS;
        char[] buf = new char[length * 2];
        int bufIndex = 0;

        for(int i = offset; i < offset + length; ++i) {
            byte b = array[i];
            buf[bufIndex++] = digits[b >>> 4 & 15];
            buf[bufIndex++] = digits[b & 15];
        }

        return new String(buf);
    }

    public static String toHexString(int i) {
        return toHexString(toByteArray(i));
    }


    public static byte[] invertByteArray(byte[] byteArray){        
        byte[] result = new byte[byteArray.length];
        int row = 0;
        for (int i = result.length-1; i >= 0; i--) {
            result[row++] = byteArray[i];
        }
        
        return result;        
    }

    /**
     * Convert the byte array to an int.
     *
     * @param b The byte array
     * @return The integer
     */
    public static int byteArrayToInt(byte[] b) {
        return byteArrayToNumericType(b, b.length - 4, 4);
    }

    /**
     * Convert the byte array to an short
     *
     * @param b The byte array
     * @return The integer
     */
    public static short byteArrayToShort(byte[] b) {
        return (short) byteArrayToNumericType(b, b.length - 2, 2);
    }

    /**
     * Convert the byte array to String
     * @param b The byte array
     * @return 
     */
    public static String byteArrayToHexString(byte[] b) {
        String result = "";
        if(b == null)
            return result;
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);

            result += " ";
        }
        return result;
    }

    public static String arrayListToHexString(List<Byte> collectionBytes) {
        StringBuilder result = new StringBuilder();
        for ( int i = 0; i < collectionBytes.size(); i++ ) {
            result.append(Integer.toString(( collectionBytes.get(i) & 0xff ) + 0x100, 16).substring(1));

            result.append(" ");
        }
        return result.toString();
    }

    /**
     * Convert the byte array to an int starting from the given offset.
     *
     * @param b The byte array
     * @param offset The array offset
     * @return The integer
     */
    public static int byteArrayToNumericType(byte[] b, int offset, int typeLenght) {
        int value = 0;
        for (int i = 0; i < typeLenght; i++) {
            int shift = (typeLenght - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }

    public static byte[] hexStringToByteArray(String hexString) {
        if (hexString.length() % 2 != 0) {
            hexString = "0" + hexString;
        }

        byte[] cliBs = new byte[hexString.length() / 2];

        for (int i = 0; i < hexString.length(); i += 2) {
            char first = hexString.charAt(i);
            char second = hexString.charAt(i + 1);

            cliBs[i / 2] = (byte) ((Character.digit(first, 16) << 4)
                    + Character.digit(second, 16));
        }
        return cliBs;
    }
    
    public static byte[] flatten(byte[]... arrs) {
        int L = 0;
        for (byte[] arr : arrs) {
            L += arr.length;
        }
        byte[] ret = new byte[L];
        int start = 0;
        for (byte[] arr : arrs) {
            System.arraycopy(arr, 0, ret, start, arr.length);
            start += arr.length;
        }
        return ret;
    }
  
  public static byte[] flatten(ArrayList<byte []> arrs) {
        int L = 0;
        for (byte[] arr : arrs) {
            L += arr.length;
        }
        byte[] ret = new byte[L];
        int start = 0;
        for (byte[] arr : arrs) {
            System.arraycopy(arr, 0, ret, start, arr.length);
            start += arr.length;
        }
        return ret;
    }

}
