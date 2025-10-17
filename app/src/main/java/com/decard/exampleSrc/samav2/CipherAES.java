/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.samav2;

import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author duma
 */
public class  CipherAES {
    private static final String TAG = CipherAES.class.getSimpleName();
    
    //private static final String UNICODE_FORMAT = "UTF8";
    public static final String DESEDE_ENCRYPTION_SCHEME = "AES";
    //private KeySpec ks;
//    private SecretKeyFactory skf;
    private Cipher cipher;
//    byte[] arrayBytes;
//    private byte[] myEncryptionKey;
    //byte[] ivBytes = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    //    ,(byte)0x00,(byte)0x00,(byte)0x00};
    private final String myEncryptionScheme = "AES/CBC/NoPadding";
    SecretKey key;
    
    private byte [] ivBytes;

    public CipherAES (byte[] keyByte) {
        try {
//          
            key = new SecretKeySpec(keyByte, "AES");
//         
            cipher = Cipher.getInstance(myEncryptionScheme);
            
            ivBytes = new byte[16];
            for (int i = 0; i < ivBytes.length; i++) {
                ivBytes[i] = (byte) 0x00;                
            }
            
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } 
    }


    public byte[] encrypt(byte[] unencryptedByte) {
        byte[] encryptedText = new byte[16];
        try {
            
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            encryptedText = cipher.update(unencryptedByte);
            cipher.doFinal();
            
            System.arraycopy(encryptedText, encryptedText.length-16, ivBytes, 0, 16);
         
                   
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        }
        
        return encryptedText;
    }


    public byte[] decrypt(byte[] encryptedString) {
        byte[] plainText= new byte[16];
        
        try {
            
                //cipher.init(Cipher.DECRYPT_MODE, key);
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
                plainText = cipher.update(encryptedString);
                cipher.doFinal();
                System.arraycopy(encryptedString, encryptedString.length-16, ivBytes, 0, 16);
                
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        }
            return plainText;
    
    }

    public byte[] getIvBytes() {
        return ivBytes;
    }

    public void setIvBytes(byte[] ivBytes) {
        for (int i = 0; i < ivBytes.length; i++) {
            this.ivBytes[i] = ivBytes[i];
            
        }
    }
    /**
     * 算法逻辑
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] aes_cmac(byte[] key, byte[] data) {
        // 子密钥生成
        // 步骤1，将具有密钥K的AES-128应用于全零输入块。
        byte[] L = aesEncryptNoPadding(key, new byte[16], new byte[16]);

        Log.i(TAG, "configUUIDValue  L: " + ByteArrayTools.toHexString(L));
        // 步骤2，通过以下操作得出K1：
        //如果L的最高有效位等于0，则K1是L的左移1位。
        byte[] FirstSubkey = Rol(L);
        if ((L[0] & 0x80) == 0x80) {
            // 否则，K1是const_Rb的异或和L左移1位。
            FirstSubkey[15] ^= 0x87;
        }
//        Log.i(TAG, "configUUIDValue  K1: "+ HexDump.toHexString(FirstSubkey));
//        FirstSubkey = ByteUtils.hexStr2Bytes("AC362C7FCCE2BD996153C64B7D39A82A");

        Log.i(TAG, "configUUIDValue  K1: " + ByteArrayTools.toHexString(FirstSubkey));
        // 步骤3，通过以下操作得出K2：
        //如果K1的最高有效位等于0，则K2是K1左移1位
        byte[] SecondSubkey = Rol(FirstSubkey);
        if ((FirstSubkey[0] & 0x80) == 0x80) {
            // 否则，K2是const_Rb的异或，且K1左移1位
            SecondSubkey[15] ^= 0x87;
        }

//        Log.i(TAG, "configUUIDValue  K2: "+ HexDump.toHexString(SecondSubkey));
//        SecondSubkey = ByteUtils.hexStr2Bytes("586C58FF99C57B32C2A78C96FA7350D3");
        Log.i(TAG, "configUUIDValue  K2: " + ByteArrayTools.toHexString(SecondSubkey));
        Log.i(TAG, "configUUIDValue  data: " + ByteArrayTools.toHexString(data));
        // MAC 计算
        if (((data.length != 0) && (data.length % 16 == 0)) == true) {
            //如果输入消息块的大小等于块大小（128位）
            // 最后一个块在处理之前应与K1异或
            for (int j = 0; j < FirstSubkey.length; j++) {
                data[data.length - 16 + j] ^= FirstSubkey[j];
            }

        } else {
            // 否则，最后一个块应填充10 ^ i
            byte[] padding = new byte[16 - data.length % 16];
            padding[0] = (byte) 0x80;
            byte[] newData = new byte[data.length + padding.length];
            System.arraycopy(data, 0, newData, 0, data.length);
            System.arraycopy(padding, 0, newData, data.length, padding.length);
            //   data = data.Concat<byte>(padding.AsEnumerable()).ToArray();
            // 并与K2进行异或运算
            for (int j = 0; j < SecondSubkey.length; j++) {
                newData[newData.length - 16 + j] ^= SecondSubkey[j];
            }
            data = newData;
        }

        Log.i(TAG, "configUUIDValue  data1: " + ByteArrayTools.toHexString(data));

        // 先前处理的结果将是最后一次加密的输入。
        byte[] encResult = aesEncryptNoPadding(key, new byte[16], data);
        // 先前处理的结果将是最后一次加密的输入。
        byte[] HashValue = new byte[16];
        System.arraycopy(encResult, encResult.length - HashValue.length, HashValue, 0, HashValue.length);
        Log.i(TAG, "configUUIDValue  data HashValue: " + ByteArrayTools.toHexString(HashValue));

        return HashValue;

    }
    public static byte[] aes_cmac_av2(byte[] key, byte[] data){
        byte[] hash = aes_cmac(key,data);
        if(hash == null)
            return null;
        byte[] cmac = new byte[8];
        for(int i = 0;i < 8;i++){
            cmac[i] = hash[i * 2 + 1];
        }
        return cmac;
    }
    private static byte[] Rol(byte[] b) {
        byte[] output = new byte[b.length];
        byte overflow = 0;

        for (int i = b.length - 1; i >= 0; i--) {
            output[i] = (byte) (b[i] << 1);
            output[i] |= overflow;
            if ((b[i] & 0x80) > 0) {
                overflow = 1;
            } else {
                overflow = 0;
            }
        }
        return output;
    }

    /**
     * AES加密
     *
     * @param keys
     * @param iv
     * @param data
     * @return
     */
    public static byte[] aesEncryptNoPadding(byte[] keys, byte[] iv, byte[] data) {
        try {
            //1.根据字节数组生成AES密钥
            SecretKey key = new SecretKeySpec(keys, "AES");
            //2.根据指定算法AES自成密码器 "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //3.CBC模式需要向量vi
            IvParameterSpec ivps = new IvParameterSpec(iv);
            //4.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.ENCRYPT_MODE, key, ivps);
            //5.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
            byte[] byte_encode = data;
            //6.根据密码器的初始化方式--加密：将数据加密
            byte[] byte_AES = cipher.doFinal(byte_encode);
            Log.i(TAG, "aesEncryptNoPadding: keys:  " + ByteArrayTools.toHexString(keys));
            Log.i(TAG, "aesEncryptNoPadding: data:  "+ByteArrayTools.toHexString(data));
            Log.i(TAG, "aesEncryptNoPadding: cipher:"+ByteArrayTools.toHexString(byte_AES));
            //7.返回
            return byte_AES;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] aesEncryptPadding(byte[] keys, byte[] iv, byte[] data)  {
        try {
            //1.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(keys, "AES");
            //2.根据指定算法AES自成密码器 "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            //3.CBC模式需要向量vi
            IvParameterSpec ivps = new IvParameterSpec(iv);
            //4.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.ENCRYPT_MODE, key,ivps);
            //5.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
            byte [] byte_encode=data;
            //6.根据密码器的初始化方式--加密：将数据加密
            byte [] byte_AES=cipher.doFinal(byte_encode);
            //7.返回
            return byte_AES;

        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] aesDecryptPadding(byte[] keys, byte[] iv, byte[] data)  {
        try {
            //1.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(keys, "AES");
            //2.根据指定算法AES自成密码器 "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            //3.CBC模式需要向量vi
            IvParameterSpec ivps = new IvParameterSpec(iv);
            //4.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.DECRYPT_MODE, key,ivps);
            //5.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
            byte [] byte_encode=data;
            //6.根据密码器的初始化方式--加密：将数据加密
            byte [] byte_AES=cipher.doFinal(byte_encode);
            //7.返回
            return byte_AES;

        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] aesDecryptNoPadding(byte[] keys, byte[] iv, byte[] data)  {
        try {
            //1.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(keys, "AES");
            //2.根据指定算法AES自成密码器 "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //3.CBC模式需要向量vi
            IvParameterSpec ivps = new IvParameterSpec(iv);
            //4.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.DECRYPT_MODE, key,ivps);
            //5.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
            byte [] byte_encode=data;
            //6.根据密码器的初始化方式--加密：将数据加密
            byte [] byte_AES = cipher.doFinal(byte_encode);
            //7.返回
            return byte_AES;

        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
    public byte [] hashCMAC(byte [] message) {

        byte [] hash = null;
        byte [] res = new byte [8];
        
        try {
            //Security.addProvider(new BouncyCastleProvider());
            
            Mac mac = Mac.getInstance("aescmac");
            
            mac.init(key);
            hash = mac.doFinal(message);
            
            for (int i = 0; i < hash.length; i++) {
                if (i%2 != 0)
                    res[i/2] = hash[i];
            }
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TAG).log(Level.SEVERE, null, ex);
        }
        
//        Log.i(TAG, "hash: [ " + ByteArrayTools.byteArrayToHexString(hash) + " ]");
//        Log.i(TAG, "res cmac: [ " + ByteArrayTools.byteArrayToHexString(res) + " ]");

        
        return res;
    }
}


    

   
