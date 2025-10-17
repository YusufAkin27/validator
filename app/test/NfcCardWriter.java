package com.example.nfcreader;

import javax.smartcardio.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.util.Map;

public class NfcCardWriter {
    private CardChannel channel;
    private ObjectMapper objectMapper;
    
    // AES-GCM parametreleri (sunucu ile aynı)
    private static final int IV_SIZE = 12; // bytes
    private static final int TAG_BITS = 128; // AES-GCM tag bits
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    
    // Master Key - Sunucudaki masterKey ile aynı olmalı!
    // UYARI: Gerçek uygulamada bu anahtarı KeyStore'dan yükleyin!
    private static final byte[] MASTER_KEY = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
        (byte)0xAB, (byte)0xF7, 0x15, (byte)0x88, 0x09, (byte)0xCF, 0x4F, 0x3C,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88,
        (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 0x00
    };
    
    // Kart için özel MIFARE anahtarı
    private static final byte[] CARD_KEY_A = {
        (byte)0xA1, (byte)0xB2, (byte)0xC3, (byte)0xD4, (byte)0xE5, (byte)0xF6
    };
    
    // Varsayılan MIFARE anahtarı
    private static final byte[] DEFAULT_KEY = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
    };
    
    public NfcCardWriter(CardChannel channel) {
        this.channel = channel;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * BusCard objesini şifreleyerek karta yazar - ANA METOD
     */
    public void writeBusCardToCard(BusCard busCard) throws CardException {
        try {
            System.out.println("📝 BusCard verisi şifreleniyor ve karta yazılıyor...");
            
            // BusCard'ı şifrele
            byte[] encryptedData = AESEncryption.encryptBusCardForCard(busCard);
            
            // MIFARE Classic 1K parametreleri
            final int START_BLOCK = 4;
            final int MAX_BLOCKS_ALLOWED = 45;
            
            // Blok sayısı kontrolü
            int blocksNeeded = (int)Math.ceil(encryptedData.length / 16.0);
            if (blocksNeeded > MAX_BLOCKS_ALLOWED) {
                throw new CardException("Hata: " + blocksNeeded + " blok gerekiyor; maksimum " + MAX_BLOCKS_ALLOWED);
            }
            
            System.out.println("🔢 Gerekli blok sayısı: " + blocksNeeded);
            
            // MIFARE Classic karta yaz
            writePayloadToMifareClassic(encryptedData, START_BLOCK);
            
            // Access bits'i ayarla
            configureAccessBits(START_BLOCK, blocksNeeded);
            
            System.out.println("✅ BusCard verisi başarıyla yazıldı!");
            
        } catch (Exception e) {
            throw new CardException("BusCard yazılamadı: " + e.getMessage());
        }
    }
    
    /**
     * Kart verilerini şifreleyerek yazar - ESKİ METOD (API uyumluluğu için)
     * Sunucudan gelen JSON response'u işler
     */
    public void writeCardData(String jsonData) throws CardException {
        try {
            JsonNode data = objectMapper.readTree(jsonData);
            
            int startSector = data.get("startSector").asInt();
            int startBlockOffset = data.get("startBlockOffset").asInt();
            String packageBase64 = data.get("packageBase64").asText();
            int maxBlocks = data.get("maxBlocks").asInt();
            
            // Base64 veriyi decode et (bu zaten AES-GCM ile şifrelenmiş)
            byte[] encryptedPackage = Base64.getDecoder().decode(packageBase64);
            
            System.out.println("📝 Kart verisi yazılıyor...");
            System.out.println("📍 Başlangıç Sektör: " + startSector);
            System.out.println("📍 Başlangıç Blok: " + startBlockOffset);
            System.out.println("📦 Şifreli Veri Boyutu: " + encryptedPackage.length + " byte");
            System.out.println("🔢 Maksimum Blok: " + maxBlocks);
            
            // Önce sektörlerin anahtarlarını değiştir (güvenlik için)
            int endSector = startSector + (maxBlocks / 3) + 1;
            changeAllSectorKeys(startSector, endSector);
            
            // Şifrelenmiş paketi bloklara böl ve yaz
            writeDataToBlocksSafe(encryptedPackage, startSector, startBlockOffset, maxBlocks);
            
            System.out.println("✅ Kart verisi başarıyla yazıldı ve korundu!");
            
        } catch (Exception e) {
            throw new CardException("Kart verisi yazılamadı: " + e.getMessage());
        }
    }
    
    /**
     * Tüm kullanılacak sektörlerin anahtarlarını değiştirir
     */
    private void changeAllSectorKeys(int startSector, int endSector) throws CardException {
        System.out.println("🔑 Sektör anahtarları değiştiriliyor...");
        
        for (int sector = startSector; sector <= endSector; sector++) {
            try {
                changeSectorKey(sector);
                System.out.println("✓ Sektör " + sector + " anahtarı güncellendi");
            } catch (CardException e) {
                System.out.println("⚠️ Sektör " + sector + " zaten güncellenmiş olabilir, devam ediliyor...");
            }
        }
    }
    
    /**
     * Bir sektörün anahtarını değiştirir
     */
    private void changeSectorKey(int sector) throws CardException {
        try {
            // Önce varsayılan anahtarla kimlik doğrula
            authenticateWithKey(sector, 3, DEFAULT_KEY, true);
            
            // Trailer bloğunu oku
            int trailerBlock = sector * 4 + 3;
            byte[] trailerData = new byte[16];
            
            // Yeni Key A
            System.arraycopy(CARD_KEY_A, 0, trailerData, 0, 6);
            
            // Access bits (okuma/yazma için Key A gerekli)
            trailerData[6] = (byte)0xFF;
            trailerData[7] = 0x07;
            trailerData[8] = (byte)0x80;
            trailerData[9] = 0x69;
            
            // Key B (kullanmıyoruz ama ayarlayalım)
            byte[] keyB = {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
            System.arraycopy(keyB, 0, trailerData, 10, 6);
            
            // Trailer bloğunu yaz
            writeBlockDirect(trailerBlock, trailerData);
            
        } catch (Exception e) {
            throw new CardException("Sektör anahtarı değiştirilemedi: " + e.getMessage());
        }
    }
    
    /**
     * Güvenli veri yazma - retry mekanizması ile
     */
    private void writeDataToBlocksSafe(byte[] data, int startSector, int startBlockOffset, int maxBlocks) throws CardException {
        int blockSize = 16;
        int currentSector = startSector;
        int currentBlock = startBlockOffset;
        int dataIndex = 0;
        int blocksWritten = 0;
        
        long startTime = System.currentTimeMillis();
        final long MAX_WRITE_TIME = 30000; // 30 saniye
        final int MAX_RETRY_ATTEMPTS = 3;
        
        System.out.println("🔐 Güvenli kart yazma başlatılıyor...");
        System.out.println("📊 Toplam veri: " + data.length + " byte, Maksimum blok: " + maxBlocks);
        
        while (dataIndex < data.length && blocksWritten < maxBlocks) {
            // Timeout kontrolü
            if (System.currentTimeMillis() - startTime > MAX_WRITE_TIME) {
                throw new CardException("Kart yazma işlemi zaman aşımına uğradı (30 saniye)");
            }
            
            // Trailer bloğu atla (her sektörün son bloğu)
            if (currentBlock == 3) {
                currentBlock = 0;
                currentSector++;
                continue;
            }
            
            // Blok verisi hazırla
            byte[] blockData = new byte[blockSize];
            int bytesToWrite = Math.min(blockSize, data.length - dataIndex);
            
            System.arraycopy(data, dataIndex, blockData, 0, bytesToWrite);
            
            // Boş kalan kısmı sıfırlarla doldur
            if (bytesToWrite < blockSize) {
                for (int i = bytesToWrite; i < blockSize; i++) {
                    blockData[i] = 0x00;
                }
            }
            
            // Bloku güvenli şekilde yaz
            boolean writeSuccess = writeBlockWithRetry(currentSector, currentBlock, blockData, MAX_RETRY_ATTEMPTS);
            
            if (!writeSuccess) {
                throw new CardException("Blok yazılamadı: Sektör " + currentSector + ", Blok " + currentBlock);
            }
            
            System.out.println("✅ Sektör " + currentSector + ", Blok " + currentBlock + 
                             " yazıldı (" + bytesToWrite + " byte)");
            
            dataIndex += bytesToWrite;
            blocksWritten++;
            
            // Sonraki bloka geç
            currentBlock++;
            if (currentBlock >= 4) {
                currentBlock = 0;
                currentSector++;
            }
            
            // Her 5 blokta bir kısa bekleme
            if (blocksWritten % 5 == 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new CardException("Yazma işlemi kesintiye uğradı");
                }
            }
        }
        
        System.out.println("🎉 Güvenli yazma tamamlandı! Toplam " + blocksWritten + " blok yazıldı.");
    }
    
    /**
     * Retry mekanizması ile blok yazma
     */
    private boolean writeBlockWithRetry(int sector, int block, byte[] data, int maxRetries) {
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                writeBlock(sector, block, data);
                return true;
            } catch (CardException e) {
                System.out.println("⚠️ Deneme " + attempt + "/" + maxRetries + " başarısız: " + e.getMessage());
                
                if (attempt < maxRetries) {
                    try {
                        Thread.sleep(200 * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * Anahtarla kimlik doğrulama
     */
    private void authenticateWithKey(int sector, int block, byte[] key, boolean useKeyA) throws CardException {
        // Anahtarı yükle
        byte[] loadKeyCmd = new byte[11];
        loadKeyCmd[0] = (byte)0xFF;
        loadKeyCmd[1] = (byte)0x82;
        loadKeyCmd[2] = 0x00;
        loadKeyCmd[3] = 0x00;
        loadKeyCmd[4] = 0x06;
        System.arraycopy(key, 0, loadKeyCmd, 5, 6);
        
        ResponseAPDU response = channel.transmit(new CommandAPDU(loadKeyCmd));
        if (response.getSW() != 0x9000) {
            throw new CardException("Anahtar yüklenemedi. SW: " + String.format("%04X", response.getSW()));
        }
        
        // Kimlik doğrulama
        byte[] authCmd = {
            (byte)0xFF, (byte)0x86, 0x00, 0x00, 0x05,
            0x01, 0x00, (byte)(sector * 4 + block), 
            useKeyA ? (byte)0x60 : (byte)0x61, 
            0x00
        };
        
        response = channel.transmit(new CommandAPDU(authCmd));
        if (response.getSW() != 0x9000) {
            throw new CardException("Kimlik doğrulama başarısız. SW: " + String.format("%04X", response.getSW()));
        }
    }
    
    /**
     * Tek bir bloku yazar
     */
    private void writeBlock(int sector, int block, byte[] data) throws CardException {
        try {
            // Özel anahtarla kimlik doğrula
            authenticateWithKey(sector, block, CARD_KEY_A, true);
            
            // Bloku yaz
            writeBlockDirect(sector * 4 + block, data);
            
        } catch (Exception e) {
            throw new CardException("Blok yazma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Blok numarasına direkt yazar
     */
    private void writeBlockDirect(int blockNumber, byte[] data) throws CardException {
        byte[] writeCmd = new byte[21];
        writeCmd[0] = (byte)0xFF;
        writeCmd[1] = (byte)0xD6;
        writeCmd[2] = 0x00;
        writeCmd[3] = (byte)blockNumber;
        writeCmd[4] = 0x10;
        
        System.arraycopy(data, 0, writeCmd, 5, 16);
        
        ResponseAPDU response = channel.transmit(new CommandAPDU(writeCmd));
        if (response.getSW() != 0x9000) {
            throw new CardException("Blok yazılamadı. SW: " + String.format("%04X", response.getSW()));
        }
    }
    
    /**
     * Şifrelenmiş veriyi karttan okur ve çözer
     * Sunucu tarafındaki encryptWithAesGcm metoduyla uyumlu
     */
    public Map<String, Object> readAndDecryptCardData(int startSector, int startBlockOffset, int maxBlocks) throws CardException {
        try {
            System.out.println("📖 Kart verisi okunuyor...");
            
            // Şifrelenmiş paketi oku
            byte[] encryptedPackage = readDataFromBlocks(startSector, startBlockOffset, maxBlocks);
            
            System.out.println("🔓 Veri çözülüyor...");
            
            // Paket yapısı: [IV (12 byte)] [Encrypted Data] [Auth Tag (16 byte)]
            // AES-GCM çıktısı zaten IV + ciphertext + tag şeklinde
            
            // IV'yi ayır
            byte[] iv = new byte[IV_SIZE];
            System.arraycopy(encryptedPackage, 0, iv, 0, IV_SIZE);
            
            // Şifreli veri + tag
            byte[] ciphertextAndTag = new byte[encryptedPackage.length - IV_SIZE];
            System.arraycopy(encryptedPackage, IV_SIZE, ciphertextAndTag, 0, ciphertextAndTag.length);
            
            // Sunucudaki dataKey'i simüle et (gerçek uygulamada karttan alınmalı veya sunucudan sorgulanmalı)
            // ⚠️ DİKKAT: Gerçek uygulamada bu şekilde yapılmamalı!
            // Seçenek 1: DataKey'i kartın metadata'sından al
            // Seçenek 2: UID ile sunucudan dataKey iste
            
            System.out.println("⚠️ UYARI: DataKey simülasyonu kullanılıyor!");
            System.out.println("📌 Gerçek uygulamada UID ile sunucudan dataKey istenmelidir!");
            
            // Şimdilik veriyi Base64 olarak döndürelim (sunucu tarafında çözülmesi için)
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedPackage);
            
            Map<String, Object> result = new java.util.HashMap<>();
            result.put("encryptedData", encryptedBase64);
            result.put("iv", Base64.getEncoder().encodeToString(iv));
            result.put("requiresServerDecryption", true);
            result.put("message", "Veri okundu, sunucu tarafında çözülmeli");
            
            System.out.println("✅ Veri başarıyla okundu!");
            
            return result;
            
        } catch (Exception e) {
            throw new CardException("Veri okunamadı: " + e.getMessage());
        }
    }
    
    /**
     * Bloklardan veri okur
     */
    private byte[] readDataFromBlocks(int startSector, int startBlockOffset, int maxBlocks) throws CardException {
        // Gerçek veri boyutunu bulmak için önce tahmini oku
        int estimatedSize = maxBlocks * 16;
        byte[] allData = new byte[estimatedSize];
        
        int currentSector = startSector;
        int currentBlock = startBlockOffset;
        int dataIndex = 0;
        int blocksRead = 0;
        
        while (blocksRead < maxBlocks) {
            if (currentBlock == 3) {
                currentBlock = 0;
                currentSector++;
                continue;
            }
            
            byte[] blockData = readBlock(currentSector, currentBlock);
            System.arraycopy(blockData, 0, allData, dataIndex, 16);
            
            System.out.println("📖 Sektör " + currentSector + ", Blok " + currentBlock + " okundu");
            
            dataIndex += 16;
            blocksRead++;
            currentBlock++;
            
            if (currentBlock >= 4) {
                currentBlock = 0;
                currentSector++;
            }
        }
        
        // Gerçek veri boyutunu bul (sondaki sıfırları çıkar)
        int actualSize = dataIndex;
        for (int i = dataIndex - 1; i >= 0; i--) {
            if (allData[i] != 0) {
                actualSize = i + 1;
                break;
            }
        }
        
        return java.util.Arrays.copyOf(allData, actualSize);
    }
    
    /**
     * Tek bir bloku okur
     */
    public byte[] readBlock(int sector, int block) throws CardException {
        try {
            // Özel anahtarla kimlik doğrula
            authenticateWithKey(sector, block, CARD_KEY_A, true);
            
            // Bloku oku
            byte[] readCmd = {
                (byte)0xFF, (byte)0xB0, 0x00, (byte)(sector * 4 + block), 0x10
            };
            
            ResponseAPDU response = channel.transmit(new CommandAPDU(readCmd));
            if (response.getSW() != 0x9000) {
                throw new CardException("Blok okunamadı. SW: " + String.format("%04X", response.getSW()));
            }
            
            return response.getData();
            
        } catch (Exception e) {
            throw new CardException("Blok okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * MIFARE Classic karta payload yazar (NFCCardWriter'dan alındı)
     */
    private void writePayloadToMifareClassic(byte[] fullPayload, int startBlock) throws CardException {
        System.out.println("📀 MIFARE Classic 1K karta veri yazılıyor...");

        final byte[] DEFAULT_KEY = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        final byte[] ALT_KEY_A   = {(byte)0xA0,(byte)0xA1,(byte)0xA2,(byte)0xA3,(byte)0xA4,(byte)0xA5};
        final byte[] ALT_KEY_B   = {(byte)0xB0,(byte)0xB1,(byte)0xB2,(byte)0xB3,(byte)0xB4,(byte)0xB5};
        
        // Daha fazla anahtar deneyelim
        final byte[] ZERO_KEY = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        final byte[] A0A0_KEY = {(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0};
        final byte[] D3F7_KEY = {(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7};

        int blocksNeeded = (int) Math.ceil(fullPayload.length / 16.0);
        int currentBlock = startBlock;
        int index = 0;

        while (index < fullPayload.length) {
            int sector = currentBlock / 4;
            int blockInSector = currentBlock % 4;

            if (blockInSector == 0) {
                boolean authOK = false;

                // Daha fazla anahtar dene
                byte[][] keyList = {DEFAULT_KEY, ALT_KEY_A, ALT_KEY_B, ZERO_KEY, A0A0_KEY, D3F7_KEY};
                for (byte[] key : keyList) {
                    if (authenticateSector(currentBlock, key, (byte)0x60)) {
                        System.out.println("🔑 Sektör " + sector + " Key A ile doğrulandı (" + bytesToHex(key) + ")");
                        authOK = true;
                        break;
                    } else if (authenticateSector(currentBlock, key, (byte)0x61)) {
                        System.out.println("🔑 Sektör " + sector + " Key B ile doğrulandı (" + bytesToHex(key) + ")");
                        authOK = true;
                        break;
                    }
                }

                if (!authOK) {
                    System.out.println("⚠️ Sektör " + sector + " kimlik doğrulama başarısız, atlanıyor...");
                    // Bu sektörü atla ve bir sonrakine geç
                    currentBlock = ((sector + 1) * 4);
                    continue;
                }
            }

            if (blockInSector == 3) {
                System.out.println("⏭️ Trailer blok (blok " + currentBlock + ") atlandı.");
                currentBlock++;
                continue;
            }

            byte[] blockData = new byte[16];
            int toCopy = Math.min(16, fullPayload.length - index);
            System.arraycopy(fullPayload, index, blockData, 0, toCopy);

            writeBlockDirect(currentBlock, blockData);
            System.out.println("✓ Blok " + currentBlock + " yazıldı (" + toCopy + " byte)");

            index += toCopy;
            currentBlock++;
            
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CardException("Yazma işlemi kesintiye uğradı");
            }
        }

        System.out.println("✅ Yazma işlemi tamamlandı!");
    }
    
    /**
     * Sektör kimlik doğrulama (NFCCardWriter'dan alındı)
     */
    private boolean authenticateSector(int block, byte[] key, byte keyType) {
        try {
            byte[] loadKey = new byte[]{
                    (byte)0xFF, (byte)0x82, 0x00, 0x00, 0x06,
                    key[0], key[1], key[2], key[3], key[4], key[5]
            };
            ResponseAPDU loadResp = channel.transmit(new CommandAPDU(loadKey));
            if (loadResp.getSW() != 0x9000) return false;

            byte[] auth = new byte[]{
                    (byte)0xFF, (byte)0x86, 0x00, 0x00, 0x05,
                    0x01, 0x00, (byte)block, keyType, 0x00
            };
            ResponseAPDU resp = channel.transmit(new CommandAPDU(auth));
            return resp.getSW() == 0x9000;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Access bits ayarlar (NFCCardWriter'dan alındı)
     */
    private void configureAccessBits(int startBlock, int blockCount) throws CardException {
        System.out.println("\n🔒 Access bits ayarlanıyor...");

        final String KEY_A_HEX = "A0 A1 A2 A3 A4 A5";
        final String KEY_B_HEX = "B0 B1 B2 B3 B4 B5";
        final byte KEY_TYPE_A = (byte) 0x60;
        final byte KEY_SLOT = 0x00;
        
        byte[] keyA = hexStringToBytes(KEY_A_HEX);
        byte[] keyB = hexStringToBytes(KEY_B_HEX);

        int startSector = startBlock / 4;
        int endSector = (startBlock + blockCount - 1) / 4;

        for (int sector = startSector; sector <= endSector; sector++) {
            int trailerBlock = (sector * 4) + 3;

            byte[] authApdu = new byte[] {
                    (byte)0xFF, (byte)0x86, 0x00, 0x00, 0x05,
                    0x01, 0x00, (byte)(trailerBlock & 0xFF), KEY_TYPE_A, KEY_SLOT
            };

            ResponseAPDU authResp = channel.transmit(new CommandAPDU(authApdu));
            if (authResp.getSW() != 0x9000) {
                System.out.println("⚠️ Sektör " + sector + " trailer authentication başarısız, atlanıyor.");
                continue;
            }

            byte[] trailerData = new byte[16];
            System.arraycopy(keyA, 0, trailerData, 0, 6);
            trailerData[6] = (byte)0xFF;
            trailerData[7] = (byte)0x07;
            trailerData[8] = (byte)0x80;
            trailerData[9] = (byte)0x69;
            System.arraycopy(keyB, 0, trailerData, 10, 6);

            writeBlockDirect(trailerBlock, trailerData);
            System.out.println("✓ Sektör " + sector + " access bits ayarlandı.");

            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CardException("Access bits ayarlama kesintiye uğradı");
            }
        }
    }
    
    /**
     * Hex string'i byte array'e çevirir
     */
    private byte[] hexStringToBytes(String hex) {
        if (hex == null) return null;
        hex = hex.replaceAll("[^0-9A-Fa-f]", "");
        if (hex.length() % 2 != 0) return null;
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
        }
        return out;
    }

    /**
     * Byte dizisini hex string'e çevirir
     */
    private String bytesToHex(byte[] bytes) {
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