package com.example.nfcreader;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Arrays;

public class AESEncryption {
    
    // AES şifreleme anahtarı (NFCCardWriter ile aynı)
    private static final String AES_PASSPHRASE = "5de7677623ddf99c244031c1a5fbb52e212ffae70ffa7f4abbfec793b07c3c82";
    
    /**
     * BusCard objesini JSON string'e çevirir
     */
    public static String createJsonFromBusCard(BusCard busCard) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"id\":").append(busCard.getId() != null ? busCard.getId() : "null").append(",");
        json.append("\"cardNumber\":\"").append(busCard.getCardNumber() != null ? busCard.getCardNumber() : "").append("\",");
        json.append("\"fullName\":\"").append(busCard.getFullName() != null ? busCard.getFullName() : "").append("\",");
        json.append("\"type\":\"").append(busCard.getType() != null ? busCard.getType().name() : "").append("\",");
        json.append("\"status\":\"").append(busCard.getStatus() != null ? busCard.getStatus().name() : "").append("\",");
        json.append("\"balance\":").append(busCard.getBalance() != null ? busCard.getBalance() : "0").append(",");
        json.append("\"active\":").append(busCard.isActive()).append(",");
        json.append("\"issueDate\":\"").append(busCard.getIssueDate() != null ? busCard.getIssueDate().toString() : "").append("\",");
        json.append("\"expiryDate\":\"").append(busCard.getExpiryDate() != null ? busCard.getExpiryDate().toString() : "").append("\",");
        json.append("\"visaCompleted\":").append(busCard.isVisaCompleted()).append(",");
        json.append("\"lastTransactionAmount\":").append(busCard.getLastTransactionAmount() != null ? busCard.getLastTransactionAmount() : "0").append(",");
        json.append("\"lastTransactionDate\":\"").append(busCard.getLastTransactionDate() != null ? busCard.getLastTransactionDate().toString() : "").append("\",");
        json.append("\"transactionCount\":").append(busCard.getTransactionCount());
        json.append("}");
        return json.toString();
    }
    
    /**
     * BusCard objesini şifreleyerek karta yazılacak formata çevirir
     * Format: [Length(2)] + [IV(16)] + [Ciphertext] + [Hash(32)]
     */
    public static byte[] encryptBusCardForCard(BusCard busCard) throws Exception {
        // JSON oluştur
        String json = createJsonFromBusCard(busCard);
        System.out.println("📄 Oluşturulan JSON: " + json);
        
        // AES şifreleme
        byte[] aesKey256 = sha256(AES_PASSPHRASE.getBytes("UTF-8"));
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        byte[] ciphertext = aesCbcEncrypt(aesKey256, iv, json.getBytes("UTF-8"));
        
        // Hash (bütünlük kontrolü)
        byte[] hash = sha256(json.getBytes("UTF-8"));
        
        // Payload = IV || ciphertext || hash
        byte[] payload = new byte[iv.length + ciphertext.length + hash.length];
        System.arraycopy(iv, 0, payload, 0, iv.length);
        System.arraycopy(ciphertext, 0, payload, iv.length, ciphertext.length);
        System.arraycopy(hash, 0, payload, iv.length + ciphertext.length, hash.length);
        
        // Length prefix ekle (2 byte, big-endian)
        byte[] lenBytes = ByteBuffer.allocate(2).putShort((short)payload.length).array();
        byte[] fullPayload = new byte[2 + payload.length];
        System.arraycopy(lenBytes, 0, fullPayload, 0, 2);
        System.arraycopy(payload, 0, fullPayload, 2, payload.length);
        
        System.out.println("🔐 Şifrelenmiş payload boyutu: " + fullPayload.length + " byte");
        return fullPayload;
    }
    
    /**
     * Karttan okunan şifreli veriyi çözer ve BusCard objesine çevirir
     */
    public static BusCard decryptCardDataToBusCard(byte[] fullPayload) throws Exception {
        if (fullPayload == null || fullPayload.length < 2) {
            throw new Exception("Geçersiz payload boyutu");
        }
        
        // Length prefix'i oku
        int payloadLength = ByteBuffer.wrap(fullPayload, 0, 2).getShort() & 0xFFFF;
        System.out.println("📖 Payload uzunluğu: " + payloadLength);
        
        if (payloadLength > fullPayload.length - 2) {
            throw new Exception("Payload uzunluğu geçersiz!");
        }
        
        // Payload'ı çıkar
        byte[] payload = new byte[payloadLength];
        System.arraycopy(fullPayload, 2, payload, 0, payloadLength);
        
        // IV, ciphertext ve hash'i ayır
        if (payload.length < 16 + 32) { // IV(16) + hash(32) minimum
            throw new Exception("Payload çok kısa!");
        }
        
        byte[] iv = new byte[16];
        System.arraycopy(payload, 0, iv, 0, 16);
        
        byte[] hash = new byte[32];
        System.arraycopy(payload, payload.length - 32, hash, 0, 32);
        
        byte[] ciphertext = new byte[payload.length - 16 - 32];
        System.arraycopy(payload, 16, ciphertext, 0, ciphertext.length);
        
        // AES şifre çözme
        byte[] aesKey256 = sha256(AES_PASSPHRASE.getBytes("UTF-8"));
        byte[] decryptedJson = aesCbcDecrypt(aesKey256, iv, ciphertext);
        
        // Hash doğrulama
        byte[] calculatedHash = sha256(decryptedJson);
        if (!Arrays.equals(hash, calculatedHash)) {
            System.out.println("⚠️ Hash doğrulama başarısız! Veri bozulmuş olabilir.");
        } else {
            System.out.println("✅ Hash doğrulama başarılı.");
        }
        
        // JSON'u parse et
        String json = new String(decryptedJson, "UTF-8");
        System.out.println("📄 Çözülen JSON: " + json);
        
        return parseJsonToBusCard(json);
    }
    
    /**
     * JSON string'i BusCard objesine çevirir
     */
    private static BusCard parseJsonToBusCard(String json) throws Exception {
        try {
            String idStr = extractJsonValue(json, "id");
            Long id = (idStr.equals("null") || idStr.isEmpty()) ? null : Long.parseLong(idStr);
            
            String cardNumber = extractJsonValue(json, "cardNumber");
            String fullName = extractJsonValue(json, "fullName");
            
            String typeStr = extractJsonValue(json, "type");
            CardType type = (typeStr.isEmpty()) ? null : CardType.valueOf(typeStr);
            
            String statusStr = extractJsonValue(json, "status");
            CardStatus status = (statusStr.isEmpty()) ? null : CardStatus.valueOf(statusStr);
            
            String balanceStr = extractJsonValue(json, "balance");
            BigDecimal balance = (balanceStr.isEmpty()) ? BigDecimal.ZERO : new BigDecimal(balanceStr);
            
            boolean active = Boolean.parseBoolean(extractJsonValue(json, "active"));
            
            String issueDateStr = extractJsonValue(json, "issueDate");
            LocalDate issueDate = (issueDateStr.isEmpty()) ? null : LocalDate.parse(issueDateStr);
            
            String expiryDateStr = extractJsonValue(json, "expiryDate");
            LocalDate expiryDate = (expiryDateStr.isEmpty()) ? null : LocalDate.parse(expiryDateStr);
            
            boolean visaCompleted = Boolean.parseBoolean(extractJsonValue(json, "visaCompleted"));
            
            String lastTransactionAmountStr = extractJsonValue(json, "lastTransactionAmount");
            BigDecimal lastTransactionAmount = (lastTransactionAmountStr.isEmpty()) ? BigDecimal.ZERO : new BigDecimal(lastTransactionAmountStr);
            
            String lastTransactionDateStr = extractJsonValue(json, "lastTransactionDate");
            LocalDate lastTransactionDate = (lastTransactionDateStr.isEmpty()) ? null : LocalDate.parse(lastTransactionDateStr);
            
            String transactionCountStr = extractJsonValue(json, "transactionCount");
            int transactionCount = (transactionCountStr.isEmpty()) ? 0 : Integer.parseInt(transactionCountStr);
            
            return new BusCard(id, cardNumber, fullName, type, status, balance, active,
                    issueDate, expiryDate, visaCompleted, lastTransactionAmount, lastTransactionDate, transactionCount);
                    
        } catch (Exception e) {
            throw new Exception("JSON parse hatası: " + e.getMessage());
        }
    }
    
    /**
     * JSON'dan değer çıkarır
     */
    private static String extractJsonValue(String json, String key) {
        try {
            String pattern = "\"" + key + "\":";
            int startIndex = json.indexOf(pattern);
            if (startIndex == -1) return "";
            
            startIndex += pattern.length();
            
            // String değerler için
            if (json.charAt(startIndex) == '"') {
                startIndex++; // " karakterini atla
                int endIndex = json.indexOf('"', startIndex);
                return json.substring(startIndex, endIndex);
            } else {
                // Sayısal/boolean değerler için
                int endIndex = startIndex;
                while (endIndex < json.length() && 
                       json.charAt(endIndex) != ',' && 
                       json.charAt(endIndex) != '}') {
                    endIndex++;
                }
                return json.substring(startIndex, endIndex).trim();
            }
        } catch (Exception e) {
            return "";
        }
    }
    
    // ---------- Yardımcı Metodlar ----------
    
    private static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
    
    private static byte[] aesCbcEncrypt(byte[] key256, byte[] iv, byte[] plain) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key256, 0, 16, "AES");
        IvParameterSpec ivs = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ks, ivs);
        return cipher.doFinal(plain);
    }
    
    private static byte[] aesCbcDecrypt(byte[] key256, byte[] iv, byte[] ciphertext) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key256, 0, 16, "AES");
        IvParameterSpec ivs = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, ks, ivs);
        return cipher.doFinal(ciphertext);
    }
}
