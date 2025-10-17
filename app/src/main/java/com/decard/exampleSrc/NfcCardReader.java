package com.decard.exampleSrc;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

public class NfcCardReader {
    
    // ---------- ULTRAIGHT CONFIG (writer ile aynı olmalı) ----------
    private static final String AES_PASSPHRASE = "5de7677623ddf99c244031c1a5fbb52e212ffae70ffa7f4abbfec793b07c3c82";
    private static final int START_PAGE = 4; // user area start
    private static final int MAX_BLOCKS_ALLOWED = 12; // eski 16-byte block sayısı; page eşdeğeri = *4
    // ----------------------------------------------------
    
    /**
     * MIFARE Classic karttan BusCard verisi okur ve çözer - ANA METOD
     */
    public static BusCard readBusCardFromCard(byte[] fullPayload) throws Exception {
        if (fullPayload == null || fullPayload.length < 2) {
            throw new Exception("Karttan veri okunamadı veya kart boş!");
        }
        
        // AESEncryption ile çöz
        BusCard busCard = AESEncryption.decryptCardDataToBusCard(fullPayload);
        
        return busCard;
    }
    
    /**
     * Ultralight karttan veri okur ve çözer - ESKİ METOD (uyumluluk için)
     */
    public static String readUltralightCardData(byte[] payload) throws Exception {
        if (payload == null) {
            throw new Exception("Geçerli payload bulunamadı veya okuma başarısız.");
        }
        
        // Parse: IV(16) || ciphertext || hash(32)
        if (payload.length < 16 + 32) {
            throw new Exception("Payload çok küçük, işlenemiyor.");
        }
        
        byte[] iv = Arrays.copyOfRange(payload, 0, 16);
        byte[] storedHash = Arrays.copyOfRange(payload, payload.length - 32, payload.length);
        byte[] ciphertext = Arrays.copyOfRange(payload, 16, payload.length - 32);
        
        byte[] aesKey256 = sha256(AES_PASSPHRASE.getBytes("UTF-8"));
        byte[] plaintext = aesCbcDecrypt(aesKey256, iv, ciphertext);
        byte[] computedHash = sha256(plaintext);
        
        if (Arrays.equals(computedHash, storedHash)) {
            String decryptedContent = new String(plaintext, "UTF-8");
            return decryptedContent;
        } else {
            throw new Exception("Hash uyuşmadı. Muhtemelen yanlış parola veya bozulmuş veri.");
        }
    }
    
    /**
     * AES-CBC decryption
     */
    private static byte[] aesCbcDecrypt(byte[] key256, byte[] iv, byte[] cipherText) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key256, 0, 16, "AES");
        IvParameterSpec ivs = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, ks, ivs);
        return cipher.doFinal(cipherText);
    }
    
    /**
     * SHA-256 hash
     */
    private static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
    
    /**
     * Byte dizisini hex string'e çevirir
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
}