package com.example.nfcreader;

import javax.smartcardio.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

public class NfcCardReader {
    private TerminalFactory terminalFactory;
    private CardTerminal terminal;
    private Card card;
    public CardChannel channel;
    
    // ---------- ULTRAIGHT CONFIG (writer ile aynı olmalı) ----------
    private static final String AES_PASSPHRASE = "5de7677623ddf99c244031c1a5fbb52e212ffae70ffa7f4abbfec793b07c3c82";
    private static final int START_PAGE = 4; // user area start
    private static final int MAX_BLOCKS_ALLOWED = 12; // eski 16-byte block sayısı; page eşdeğeri = *4
    // ----------------------------------------------------
    
    public NfcCardReader() throws CardException {
        try {
            terminalFactory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = terminalFactory.terminals().list();
            
            if (terminals.isEmpty()) {
                throw new CardException("NFC cihazı bulunamadı! Lütfen NFC okuyucunun bağlı olduğundan emin olun.");
            }
            
            terminal = terminals.get(0);
            System.out.println("✅ NFC Cihazı: " + terminal.getName());
            System.out.println("📡 Cihaz Hazır - Kart bekleniyor...");
            
        } catch (CardException e) {
            throw e;
        } catch (Exception e) {
            throw new CardException("NFC cihazı başlatılamadı: " + e.getMessage());
        }
    }
    
    /**
     * Kartın takılı olup olmadığını kontrol eder
     */
    public boolean isCardPresent() {
        try {
            return terminal.isCardPresent();
        } catch (CardException e) {
            System.err.println("⚠️ Kart durumu kontrol edilemedi: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Kartı bekler ve bağlantı kurar
     */
    public void waitForCardAndConnect() throws CardException, InterruptedException {
        System.out.println("⏳ Kart bekleniyor...");
        
        // Kartın takılmasını bekle
        while (!isCardPresent()) {
            Thread.sleep(100);
        }
        
        // Kart stabilize olsun diye kısa bir bekleme
        Thread.sleep(300);
        
        System.out.println("💳 Kart algılandı, bağlanılıyor...");
        
        try {
            // Kart bağlantısı kur
            card = terminal.connect("*"); // "*" = T=0 veya T=1 protokolü
            channel = card.getBasicChannel();
            
            // ATR'yi al ve göster
            byte[] atr = card.getATR().getBytes();
            System.out.println("🔍 ATR: " + bytesToHex(atr));
            
            System.out.println("✅ Kart bağlantısı başarılı!");
            
        } catch (CardException e) {
            disconnect();
            throw new CardException("Karta bağlanılamadı: " + e.getMessage());
        }
    }
    
    /**
     * Kartın UID'sini okur
     */
    public String readCardUid() throws CardException {
        if (card == null || channel == null) {
            throw new CardException("Kart bağlantısı kurulmamış!");
        }
        
        try {
            // UID okuma komutu (ISO14443A kartlar için)
            byte[] cmd = new byte[]{(byte)0xFF, (byte)0xCA, 0x00, 0x00, 0x00};
            ResponseAPDU response = channel.transmit(new CommandAPDU(cmd));
            
            if (response.getSW() == 0x9000) {
                byte[] uidBytes = response.getData();
                String uid = bytesToHex(uidBytes);
                System.out.println("🆔 Kart UID: " + uid);
                return uid;
            } else {
                throw new CardException("UID okunamadı. SW: " + String.format("%04X", response.getSW()));
            }
        } catch (CardException e) {
            throw e;
        } catch (Exception e) {
            throw new CardException("UID okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Kartın tipini kontrol eder
     */
    public String getCardType() throws CardException {
        if (card == null) {
            throw new CardException("Kart bağlantısı kurulmamış!");
        }
        
        byte[] atr = card.getATR().getBytes();
        
        // MIFARE Classic 1K tespiti
        if (atr.length >= 2) {
            // MIFARE Classic 1K tipik ATR'leri
            if ((atr[atr.length - 2] == 0x00 && atr[atr.length - 1] == 0x01) ||
                (atr.length > 10 && atr[13] == 0x00)) {
                return "MIFARE Classic 1K";
            }
        }
        
        return "Bilinmeyen Kart Tipi";
    }
    
    /**
     * Kartın çıkarılmasını bekler
     */
    public void waitForCardRemoval() throws CardException, InterruptedException {
        System.out.println("⏳ Kartın çıkarılması bekleniyor...");
        
        int checkCount = 0;
        while (isCardPresent()) {
            Thread.sleep(100);
            checkCount++;
            
            // Her 10 kontrolde bir mesaj göster
            if (checkCount % 10 == 0) {
                System.out.println("⏳ Hala bekliyor... (Kartı çıkarın)");
            }
        }
        
        System.out.println("✅ Kart çıkarıldı.");
        
        // Kart çıkarıldıktan sonra bağlantıyı kes
        disconnect();
    }
    
    /**
     * Kart bağlantısını keser
     */
    public void disconnect() {
        try {
            if (card != null) {
                card.disconnect(false);
                System.out.println("🔌 Kart bağlantısı kesildi.");
                card = null;
                channel = null;
            }
        } catch (CardException e) {
            System.err.println("⚠️ Kart bağlantısı kesilemedi: " + e.getMessage());
            card = null;
            channel = null;
        }
    }
    
    /**
     * NFC cihazını kapatır
     */
    public void close() {
        disconnect();
        terminal = null;
        terminalFactory = null;
        System.out.println("🔒 NFC okuyucu kapatıldı.");
    }
    
    /**
     * Yeniden bağlanma denemesi
     */
    public boolean reconnect(int maxAttempts) {
        System.out.println("🔄 Yeniden bağlanılıyor...");
        
        for (int i = 0; i < maxAttempts; i++) {
            try {
                disconnect();
                Thread.sleep(500);
                
                if (isCardPresent()) {
                    waitForCardAndConnect();
                    return true;
                }
            } catch (Exception e) {
                System.err.println("⚠️ Bağlantı denemesi " + (i + 1) + " başarısız: " + e.getMessage());
            }
        }
        
        return false;
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
    
    /**
     * Cihaz bilgilerini gösterir
     */
    public void printDeviceInfo() {
        try {
            System.out.println("\n📋 NFC Cihaz Bilgileri:");
            System.out.println("   Cihaz Adı: " + terminal.getName());
            System.out.println("   Kart Var: " + (isCardPresent() ? "Evet" : "Hayır"));
            
            if (card != null) {
                System.out.println("   Protokol: " + card.getProtocol());
                System.out.println("   Kart Tipi: " + getCardType());
            }
            System.out.println();
            
        } catch (Exception e) {
            System.err.println("⚠️ Cihaz bilgileri alınamadı: " + e.getMessage());
        }
    }
    
    /**
     * MIFARE Classic karttan BusCard verisi okur ve çözer - ANA METOD
     */
    public BusCard readBusCardFromCard() throws CardException {
        if (card == null || channel == null) {
            throw new CardException("Kart bağlantısı kurulmamış!");
        }
        
        try {
            System.out.println("📖 MIFARE Classic karttan BusCard verisi okunuyor...");
            
            // MIFARE Classic parametreleri
            final int START_BLOCK = 4;
            final int MAX_BLOCKS_ALLOWED = 45;
            
            // Karttan veri oku
            byte[] fullPayload = readPayloadFromMifareClassic(START_BLOCK);
            
            if (fullPayload == null || fullPayload.length < 2) {
                throw new CardException("Karttan veri okunamadı veya kart boş!");
            }
            
            // AESEncryption ile çöz
            BusCard busCard = AESEncryption.decryptCardDataToBusCard(fullPayload);
            
            System.out.println("✅ BusCard verisi başarıyla okundu ve çözüldü!");
            return busCard;
            
        } catch (Exception e) {
            throw new CardException("BusCard okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Ultralight karttan veri okur ve çözer - ESKİ METOD (uyumluluk için)
     */
    public String readUltralightCardData() throws CardException {
        if (card == null || channel == null) {
            throw new CardException("Kart bağlantısı kurulmamış!");
        }
        
        try {
            System.out.println("📖 Ultralight kart verisi okunuyor...");
            
            int maxPagesAllowed = MAX_BLOCKS_ALLOWED * 4; // page limit
            byte[] payload = readPayloadFromUltralight(channel, START_PAGE, maxPagesAllowed);

            if (payload == null) {
                throw new CardException("Geçerli payload bulunamadı veya okuma başarısız.");
            }
            
            System.out.println("✅ Okunan payload toplam byte: " + payload.length);
            
            // Parse: IV(16) || ciphertext || hash(32)
            if (payload.length < 16 + 32) {
                throw new CardException("Payload çok küçük, işlenemiyor.");
            }
            
            byte[] iv = Arrays.copyOfRange(payload, 0, 16);
            byte[] storedHash = Arrays.copyOfRange(payload, payload.length - 32, payload.length);
            byte[] ciphertext = Arrays.copyOfRange(payload, 16, payload.length - 32);
            
            byte[] aesKey256 = sha256(AES_PASSPHRASE.getBytes("UTF-8"));
            byte[] plaintext = aesCbcDecrypt(aesKey256, iv, ciphertext);
            byte[] computedHash = sha256(plaintext);
            
            if (Arrays.equals(computedHash, storedHash)) {
                System.out.println("✅ Geçerli payload bulundu. Çözülen içerik:");
                String decryptedContent = new String(plaintext, "UTF-8");
                System.out.println(decryptedContent);
                return decryptedContent;
            } else {
                throw new CardException("Hash uyuşmadı. Muhtemelen yanlış parola veya bozulmuş veri.");
            }
            
        } catch (Exception e) {
            throw new CardException("Ultralight veri okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Reads fullPayload from Ultralight:
     * - Uses PN532 READ (0x30) wrapped in PC/SC pseudo-APDU: FF 00 00 00 Lc D4 40 01 30 <page>
     * - Each READ returns 16 bytes (4 pages). We append chunks into baos until we have at least 2 bytes,
     *   read length (big-endian unsigned short) and then continue until we have (2 + length) bytes.
     *
     * Returns only the payload (no 2-byte length prefix). Returns null on error.
     */
    private byte[] readPayloadFromUltralight(CardChannel channel, int startPage, int maxPages) {
        try {
            final int pageSize = 4;        // bytes per page
            final int chunkPages = 4;      // 0x30 READ returns 4 pages = 16 bytes
            final int chunkBytes = chunkPages * pageSize; // 16

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int pagesRead = 0;
            int currentPage = startPage;

            int maxChunks = (int) Math.ceil((double) maxPages / chunkPages);

            for (int chunk = 0; chunk < maxChunks; chunk++) {
                // Build PN532 READ command wrapper: FF 00 00 00 <Lc> D4 40 01 30 <page>
                int tagCmdLen = 2; // 0x30 <page>
                int lc = 3 + tagCmdLen; // D4 40 01 + tagCmd
                byte[] apdu = new byte[5 + lc];
                apdu[0] = (byte) 0xFF; apdu[1] = (byte) 0x00; apdu[2] = (byte) 0x00; apdu[3] = (byte) 0x00;
                apdu[4] = (byte) (lc & 0xFF);
                apdu[5] = (byte) 0xD4; apdu[6] = (byte) 0x40; apdu[7] = (byte) 0x01;
                apdu[8] = (byte) 0x30; // READ
                apdu[9] = (byte) (currentPage & 0xFF);

                ResponseAPDU resp = channel.transmit(new CommandAPDU(apdu));
                if (resp.getSW() != 0x9000) {
                    System.err.println(String.format("Read SW=%04X for page %d", resp.getSW(), currentPage));
                    return null;
                }

                byte[] data = resp.getData();
                if (data == null || data.length == 0) {
                    System.err.println("Tag returned no data for page " + currentPage);
                    return null;
                }

                // PN532 response usually: D5 41 00 <...tag-data...>
                byte[] tagData;
                if (data.length >= 3 && data[0] == (byte) 0xD5 && data[1] == (byte) 0x41 && data[2] == 0x00) {
                    tagData = Arrays.copyOfRange(data, 3, data.length);
                } else {
                    tagData = data;
                }

                // We expect 16 bytes for a full chunk. If less, still append what we have.
                baos.write(tagData);
                pagesRead += (tagData.length / pageSize);
                currentPage += chunkPages; // advance by 4 pages (since READ returns 4 pages)

                // If we have at least 2 bytes, we can know expected total
                byte[] soFar = baos.toByteArray();
                if (soFar.length >= 2) {
                    int expectedLen = ByteBuffer.wrap(soFar, 0, 2).getShort() & 0xFFFF;
                    int expectedTotal = 2 + expectedLen;
                    if (soFar.length >= expectedTotal) {
                        // We read enough bytes (maybe extra padding at the end), extract payload portion
                        byte[] full = Arrays.copyOf(soFar, expectedTotal);
                        // payload = full[2..]
                        byte[] payload = Arrays.copyOfRange(full, 2, full.length);
                        return payload;
                    }
                }

                // small delay between chunks
                try { Thread.sleep(20); } catch (InterruptedException ignored) {}
            }

            // If we exit loop without returning, we didn't get expected bytes
            System.err.println("Okuma tamamlandı fakat yeterli veri gelmedi. Okunan toplam byte: " + baos.size());
            return null;

        } catch (CardException ce) {
            System.err.println("CardException in readPayloadFromUltralight: " + ce.getMessage());
            ce.printStackTrace();
            return null;
        } catch (Exception e) {
            System.err.println("Exception in readPayloadFromUltralight: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * AES-CBC decryption
     */
    private byte[] aesCbcDecrypt(byte[] key256, byte[] iv, byte[] cipherText) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key256, 0, 16, "AES");
        IvParameterSpec ivs = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, ks, ivs);
        return cipher.doFinal(cipherText);
    }
    
    /**
     * MIFARE Classic karttan payload okur (NFCCardReader'dan alındı)
     */
    private byte[] readPayloadFromMifareClassic(int startBlock) throws CardException {
        System.out.println("📖 MIFARE Classic 1K karttan veri okunuyor...");

        final byte[] DEFAULT_KEY = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        final byte[] ALT_KEY_A   = {(byte)0xA0,(byte)0xA1,(byte)0xA2,(byte)0xA3,(byte)0xA4,(byte)0xA5};
        final byte[] ALT_KEY_B   = {(byte)0xB0,(byte)0xB1,(byte)0xB2,(byte)0xB3,(byte)0xB4,(byte)0xB5};
        
        // Daha fazla anahtar deneyelim
        final byte[] ZERO_KEY = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        final byte[] A0A0_KEY = {(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0};
        final byte[] D3F7_KEY = {(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7};

        final int MAX_BLOCKS_ALLOWED = 45;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int currentBlock = startBlock;
        boolean foundData = false;

        // Maksimum 45 blok oku (11 sektör)
        for (int i = 0; i < MAX_BLOCKS_ALLOWED; i++) {
            int sector = currentBlock / 4;
            int blockInSector = currentBlock % 4;

            // Trailer blokları atla
            if (blockInSector == 3) {
                currentBlock++;
                continue;
            }

            // Sektör başında authenticate yap
            if (blockInSector == 0) {
                boolean authOK = false;

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
                    currentBlock = ((sector + 1) * 4);
                    continue;
                }
            }

            // Blok oku
            byte[] readCmd = {(byte)0xFF, (byte)0xB0, 0x00, (byte)currentBlock, 0x10};
            ResponseAPDU readResp = channel.transmit(new CommandAPDU(readCmd));
            
            if (readResp.getSW() != 0x9000) {
                System.out.println("⚠️ Blok " + currentBlock + " okunamadı (SW=" + 
                        String.format("%04X", readResp.getSW()) + ")");
                currentBlock++;
                continue;
            }

            byte[] blockData = readResp.getData();
            
            // Boş blok kontrolü (tümü 0x00 veya 0xFF ise dur)
            boolean isEmpty = true;
            for (byte b : blockData) {
                if (b != 0x00 && b != (byte)0xFF) {
                    isEmpty = false;
                    break;
                }
            }

            if (isEmpty && foundData) {
                System.out.println("✓ Boş blok bulundu, okuma tamamlandı.");
                break;
            }

            if (!isEmpty) {
                foundData = true;
                try {
                    baos.write(blockData);
                    System.out.println("✓ Blok " + currentBlock + " okundı (" + blockData.length + " byte)");
                } catch (java.io.IOException e) {
                    System.err.println("⚠️ Blok " + currentBlock + " yazma hatası: " + e.getMessage());
                }
            }

            currentBlock++;
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CardException("Okuma işlemi kesintiye uğradı");
            }
        }

        if (!foundData) {
            return null;
        }

        byte[] fullPayload = baos.toByteArray();
        System.out.println("✅ Toplam " + fullPayload.length + " byte veri okundı.");
        return fullPayload;
    }
    
    /**
     * Sektör kimlik doğrulama (NFCCardReader'dan alındı)
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
     * SHA-256 hash
     */
    private byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}