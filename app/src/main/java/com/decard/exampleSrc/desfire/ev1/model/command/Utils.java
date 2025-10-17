package com.decard.exampleSrc.desfire.ev1.model.command;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import android.view.WindowManager;

import org.w3c.dom.Node;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.StringWriter;
import java.util.List;

public class Utils {
    /**
     * 一个字节包含位的数量 8
     */
    private static final int BITS_OF_BYTE = 8;
    /**
     * 多项式
     */
    private static final int POLYNOMIAL = 0xA001;
    /**
     * 初始值
     */
    private static final int INITIAL_VALUE = 0xFFFF;

    private static final int INITIAL_VALUE_NTAG = 0x6363;
    private static final int POLYNOMIAL_NTAG = 0x8408;

    /**
     * CRC16 编码
     *
     * @param bytes 编码内容
     * @return 编码结果
     */
    public static byte[] crc16(byte[] bytes) {
        int res = INITIAL_VALUE_NTAG;
        byte[] crc = new byte[2];
        for (byte data : bytes) {
            res = res ^ (data & 0xff);
            for (int i = 0; i < BITS_OF_BYTE; i++) {
                res = (res & 0x0001) == 1 ? (res >> 1) ^ POLYNOMIAL_NTAG : res >> 1;
            }
        }
       // Log.i("crc16 ","res= " + Integer.toHexString (res));
        crc[0] = (byte)((res & 0x00FF) );
        crc[1] = (byte)((res & 0xFF00) >> 8);

        return crc;
    }

    /**
     * 翻转16位的高八位和低八位字节
     *
     * @param src 翻转数字
     * @return 翻转结果
     */
    private static int revert(int src) {
        int lowByte = (src & 0xFF00) >> 8;
        int highByte = (src & 0x00FF) << 8;
        return lowByte | highByte;
    }

    public static String getHexString (byte[] a) {
	    return getHexString(a, false);
    }
    
    public static String getHexString(byte[] a, boolean space) {
        return getHexString(a, 0, a.length, space);
    }

    public static String getHexString(byte[] data, int offset, int length, boolean space) {
        StringBuilder sb = new StringBuilder(length * 2);

        for(int i = offset; i < offset + length; i++) {
            sb.append(String.format("%02x", data[i]));
            if(space) {
                sb.append(' ');
            }
        }

        return sb.toString().toUpperCase();
    }


    public static int byteArrayToInt(byte[] b) {
        return byteArrayToInt(b, 0);
    }
    
    public static int byteArrayToInt(byte[] b, int offset) {
        return byteArrayToInt(b, offset, b.length);
    }
    
    public static int byteArrayToInt(byte[] b, int offset, int length) {
        return (int) byteArrayToLong(b, offset, length);
    }

    public static long byteArrayToLong(byte[] b, int offset, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            int shift = (length - 1 - i) * 8;
            value += (b[i + offset] & 0xFF) << shift;
        }
        return value;
    }
}