package com.decard.exampleSrc;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.decard.NDKMethod.BasicOper;
import com.decard.exampleSrc.samav2.ByteArrayTools;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Random;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import com.example.nfcreader.BusCard;
import com.example.nfcreader.CardType;
import com.example.nfcreader.CardStatus;
import com.example.nfcreader.AESEncryption;

public class MainActivity extends AppCompatActivity {
    private final String TAG = MainActivity.class.getSimpleName();
    private TextView tv;
    private Button b_open;
    
    // Yeni UI elementleri
    private TextView tvStatus;
    private TextView tvCardHolderName;
    private TextView tvCardType;
    private TextView tvCurrentBalance;
    private TextView tvDeductedAmount;
    private TextView tvRemainingBalance;
    private final int MSG_CLEAR_TEXT = 2;
    private final int MSG_APPEND_TEXT = 1;
    private final int MSG_ID_CARD = 11;
    private final int MSG_M2_CARD_READ = 12;

    // Otomatik kart okuma için
    private boolean isAutoReading = false;
    private Thread autoReadThread;

    public final int DISCOVERY_CARD_TYPEA = 0;
    public final int DISCOVERY_CARD_TYPEB = 1;
    public final int DISCOVERY_MODE_IDLE_CARD = 0;
    public final int DISCOVERY_MODE_ALL_CARD = 1;
    public final int PICC_BITRATE_TXRX_106K = 0x00;
    public final int PICC_BITRATE_TXRX_212K = 0x01;
    public final int PICC_BITRATE_TXRX_424K = 0x02;
    public final int PICC_BITRATE_TXRX_848K = 0x03;
    public final int PICC_FSD_16 = 0x00;
    public final int PICC_FSD_24 = 0x01;
    public final int PICC_FSD_32 = 0x02;
    public final int PICC_FSD_40 = 0x03;
    public final int PICC_FSD_48 = 0x04;
    public final int PICC_FSD_64 = 0x05;
    public final int PICC_FSD_96 = 0x06;
    public final int PICC_FSD_128 = 0x07;
    public final int PICC_FSD_256 = 0x08;
    public final String desfireATQA = "4403";
    
    // ---------- ULTRAIGHT CONFIG (writer ile aynı olmalı) ----------
    private static final String AES_PASSPHRASE = "5de7677623ddf99c244031c1a5fbb52e212ffae70ffa7f4abbfec793b07c3c82";
    private static final int START_PAGE = 4; // user area start
    private static final int MAX_BLOCKS_ALLOWED = 12; // eski 16-byte block sayısı; page eşdeğeri = *4
    // ----------------------------------------------------
    
    // ---------- BAKIYE KESME SİSTEMİ ----------
    private static final BigDecimal TAM_FARE = new BigDecimal("5.00");
    private static final BigDecimal OGRENCI_FARE = new BigDecimal("2.50");
    private static final BigDecimal YETISKIN_FARE = new BigDecimal("4.00");
    private static final BigDecimal YASLI_FARE = new BigDecimal("2.00");
    private static final BigDecimal ENGELLI_FARE = new BigDecimal("1.00");
    private static final BigDecimal COCUK_FARE = new BigDecimal("1.50");
    // -----------------------------------------

    /**
     * execute shell commands
     */
    public static CommandResult execCommand(String[] commands, boolean isRoot,
                                            boolean isNeedResultMsg) {
        final String COMMAND_SU = "su";
        final String COMMAND_SU_DECARD = "su_decard";
        final String COMMAND_SH = "sh";
        final String COMMAND_EXIT = "exit\n";
        final String COMMAND_LINE_END = "\n";
        int result = -1;
        if (commands == null || commands.length == 0) {
            return new CommandResult(result, null, null);
        }

        Process process = null;
        BufferedReader successResult = null;
        BufferedReader errorResult = null;
        StringBuilder successMsg = null;
        StringBuilder errorMsg = null;

        DataOutputStream os = null;
        try {
            process = Runtime.getRuntime().exec(
                    isRoot ? COMMAND_SU_DECARD : COMMAND_SH);
            os = new DataOutputStream(process.getOutputStream());
            for (String command : commands) {
                if (command == null) {
                    continue;
                }
                os.write(command.getBytes());
                os.writeBytes(COMMAND_LINE_END);
                os.flush();
            }
            os.writeBytes(COMMAND_EXIT);
            os.flush();

            result = process.waitFor();
            if (isNeedResultMsg) {
                successMsg = new StringBuilder();
                errorMsg = new StringBuilder();
                successResult = new BufferedReader(new InputStreamReader(
                        process.getInputStream()));
                errorResult = new BufferedReader(new InputStreamReader(
                        process.getErrorStream()));
                String s;
                while ((s = successResult.readLine()) != null) {
                    successMsg.append(s);
                }
                while ((s = errorResult.readLine()) != null) {
                    errorMsg.append(s);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                if (successResult != null) {
                    successResult.close();
                }
                if (errorResult != null) {
                    errorResult.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (process != null) {
                process.destroy();
            }
        }
        return new CommandResult(result, successMsg == null ? null
                : successMsg.toString(), errorMsg == null ? null
                : errorMsg.toString());
    }

    public static class CommandResult {
        public int result;
        public String successMsg;
        public String errorMsg;

        public CommandResult(int result) {
            this.result = result;
        }

        public CommandResult(int result, String successMsg, String errorMsg) {
            this.result = result;
            this.successMsg = successMsg;
            this.errorMsg = errorMsg;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        b_open = findViewById(R.id.buttonOpen);
        tv = findViewById(R.id.textView);
        
        // Yeni UI elementlerini bağla
        tvStatus = findViewById(R.id.tvStatus);
        tvCardHolderName = findViewById(R.id.tvCardHolderName);
        tvCardType = findViewById(R.id.tvCardType);
        tvCurrentBalance = findViewById(R.id.tvCurrentBalance);
        tvDeductedAmount = findViewById(R.id.tvDeductedAmount);
        tvRemainingBalance = findViewById(R.id.tvRemainingBalance);
        
        setSupportActionBar(myToolbar);
        
        // Uygulama başladığında otomatik port aç ve kart okumaya başla
        appendLog("🚀 Uygulama başlatılıyor...");
        appendLog("📡 Port açılıyor...");
        
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Port açma işlemi
                    int st = openReader();
                    if (st == 0) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                b_open.setText("Port Açık");
                                tvStatus.setText("✅ Port açık - Kart bekleniyor...");
                                appendBalanceLog("🚀 Uygulama başlatıldı");
                                appendBalanceLog("📡 Port başarıyla açıldı");
                                appendBalanceLog("🔍 Bakiye kesme sistemi aktif");
                                appendBalanceLog("💳 Kartı yaklaştırın...");
                                appendBalanceLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                            }
                        });
                        
                        // Otomatik kart okuma döngüsünü başlat
                        startAutoCardReading();
                    } else {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvStatus.setText("❌ Port açılamadı!");
                                appendBalanceLog("❌ Port açılamadı! Cihazı kontrol edin.");
                            }
                        });
                    }
                } catch (Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                                tvStatus.setText("❌ Hata oluştu!");
                                appendBalanceLog("❌ HATA: " + e.getMessage());
                        }
                    });
                }
            }
        }).start();
    }

    @SuppressLint("HandlerLeak")
    Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            if (msg.what == MSG_APPEND_TEXT) {
                tv.append((String) msg.obj + "\n");
                tv.setMovementMethod(ScrollingMovementMethod.getInstance());
                int line = tv.getLineCount();
                if (line > 20) {
                    int offset = tv.getLineCount() * tv.getLineHeight();
                    tv.scrollTo(0, offset - tv.getHeight() + tv.getLineHeight());
                }
            } else if (msg.what == MSG_CLEAR_TEXT) {
                clearTextView();
            }
        }
    };

    private void appendLog(String str1) {
        Message message = handler.obtainMessage();
        message.what = MSG_APPEND_TEXT;
        message.obj = str1;
        handler.sendMessage(message);
    }

    private void clearLog() {
        Message message = handler.obtainMessage();
        message.what = MSG_CLEAR_TEXT;
        handler.sendMessage(message);
    }

    private void clearTextView() {
        tv.setText("");
        tv.setMovementMethod(ScrollingMovementMethod.getInstance());
        tv.scrollTo(0, 0);
    }

    private int openUSBReader() {
        String port = "AUSB";
        BasicOper.dc_setLanguageEnv(1);
        BasicOper.dc_AUSB_ReqPermission(this);
        int devHandle = BasicOper.dc_open("AUSB", this, "", 0);
        if (devHandle > 0) {
            Log.d("open", "dc_open success devHandle = " + devHandle);
        }
        if (devHandle > 0) {
            appendLog("open port " + port + "success");
            return 0;
        } else {
            appendLog("open port " + port + " error");
            return -2;
        }
    }

    private int openSerialReader() {
        String port = "/dev/dc_spi32765.0";
        String portUart = "/dev/ttyUSB0";
        BasicOper.dc_setLanguageEnv(1);
        int devHandle = BasicOper.dc_open("COM", null, port, 115200);
        if (devHandle < 0) {
            port = portUart;
            devHandle = BasicOper.dc_open("COM", null, port, 115200);
        }
        if (devHandle > 0) {
            appendLog("open port " + port + " success");
            return 0;
        } else {
            appendLog("open port " + port + " error");
            return -2;
        }
    }

    private void closeReader() {
        BasicOper.dc_exit();
        appendLog("close port");
    }

    private int detectMifareCard() {
        while (true) {
            // Delay kaldırıldı - hızlandırma için
            String[] resultArr = BasicOper.dc_reset().split("\\|", -1);
            if (!resultArr[0].equals("0000")) {
                appendLog("dc_reset error");
                return -1;
            }
            resultArr = BasicOper.dc_config_card(DISCOVERY_CARD_TYPEA).split("\\|", -1);
            if (!resultArr[0].equals("0000")) {
                appendLog("dc_config_card error");
                return -1;
            }
            resultArr = BasicOper.dc_card_n_hex(DISCOVERY_MODE_ALL_CARD).split("\\|", -1);
            if (resultArr[0].equals("0000")) {
                appendLog("dc_card_n_hex success");
                return 0;
            }
        }
    }

    private int removeM1Card() {
        // Kart çıkarma beklemesi kaldırıldı - anında yeni karta geçiş
                return 0;
    }

    public int openReader() {
        int st = openUSBReader();
        if (st < 0) {
            st = openSerialReader();
        }
        return st;
    }

    private String getReaderVersion() {
        String[] resultArr = BasicOper.dc_getver().split("\\|", -1);
            if (resultArr[0].equals("0000")) {
            return resultArr[1];
        } else {
            return "";
        }
    }
    
    private boolean isReaderOpened(){
        return b_open.getText().toString().equals("Port Açık");
    }

    public void onOpenReader(View v) {
        // Port durumunu kontrol et ve logları temizle
        clearLog();
        tvStatus.setText(isReaderOpened() ? "✅ Port açık - Kart bekleniyor..." : "❌ Port kapalı!");
        appendBalanceLog("🔍 Port durumu: " + (isReaderOpened() ? "Açık" : "Kapalı"));
        appendBalanceLog("💳 Bakiye kesme sistemi aktif");
        appendBalanceLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    /**
     * MIFARE Classic karttan veri okur (NfcCardReader.java'dan birebir alındı)
     */
    private byte[] readMifareClassicData() {
        try {
            final int START_BLOCK = 4;
            final int MAX_BLOCKS_ALLOWED = 45;
            
            appendLog("📖 MIFARE Classic 1K karttan veri okunuyor...");

            final byte[] DEFAULT_KEY = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
            final byte[] ALT_KEY_A   = {(byte)0xA0,(byte)0xA1,(byte)0xA2,(byte)0xA3,(byte)0xA4,(byte)0xA5};
            final byte[] ALT_KEY_B   = {(byte)0xB0,(byte)0xB1,(byte)0xB2,(byte)0xB3,(byte)0xB4,(byte)0xB5};
            
            // Daha fazla anahtar deneyelim
            final byte[] ZERO_KEY = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
            final byte[] A0A0_KEY = {(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0,(byte)0xA0};
            final byte[] D3F7_KEY = {(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7,(byte)0xD3,(byte)0xF7};

            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            int currentBlock = START_BLOCK;
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
                            appendLog("🔑 Sektör " + sector + " Key A ile doğrulandı (" + bytesToHex(key) + ")");
                            authOK = true;
                            break;
                        } else if (authenticateSector(currentBlock, key, (byte)0x61)) {
                            appendLog("🔑 Sektör " + sector + " Key B ile doğrulandı (" + bytesToHex(key) + ")");
                            authOK = true;
                            break;
                        }
                    }

                    if (!authOK) {
                        appendLog("⚠️ Sektör " + sector + " kimlik doğrulama başarısız, atlanıyor...");
                        currentBlock = ((sector + 1) * 4);
                        continue;
                    }
                }

                // Blok oku
                String[] readResult = BasicOper.dc_read_hex(currentBlock).split("\\|", -1);
                if (readResult[0].equals("0000")) {
                    String blockData = readResult[1];
                    
                    // Hex string'i byte array'e çevir
                    byte[] blockBytes = new byte[blockData.length() / 2];
                    for (int j = 0; j < blockBytes.length; j++) {
                        blockBytes[j] = (byte) Integer.parseInt(blockData.substring(j * 2, j * 2 + 2), 16);
                    }
                    
                    // Boş blok kontrolü (tümü 0x00 veya 0xFF ise dur)
                    boolean isEmpty = true;
                    for (byte b : blockBytes) {
                        if (b != 0x00 && b != (byte)0xFF) {
                            isEmpty = false;
                            break;
                        }
                    }

                    if (isEmpty && foundData) {
                        appendLog("✓ Boş blok bulundu, okuma tamamlandı.");
                        break;
                    }

                    if (!isEmpty) {
                        foundData = true;
                        try {
                            baos.write(blockBytes);
                            appendLog("✓ Blok " + currentBlock + " okundı (" + blockBytes.length + " byte)");
                        } catch (java.io.IOException e) {
                            appendLog("⚠️ Blok " + currentBlock + " yazma hatası: " + e.getMessage());
                        }
                    }
                } else {
                    appendLog("⚠️ Blok " + currentBlock + " okunamadı (SW=" + readResult[0] + ")");
                }

                currentBlock++;
                // Delay kaldırıldı - hızlandırma için
            }

            if (!foundData) {
                return null;
            }

            byte[] fullPayload = baos.toByteArray();
            appendLog("✅ Toplam " + fullPayload.length + " byte veri okundı.");
            return fullPayload;
            
        } catch (Exception e) {
            appendLog("❌ MIFARE Classic okuma hatası: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Sektör kimlik doğrulama (NfcCardReader.java'dan alındı - BasicOper ile uyumlu)
     */
    private boolean authenticateSector(int block, byte[] key, byte keyType) {
        try {
            // Anahtarı hex string'e çevir
            String keyHex = bytesToHex(key).replace(" ", "");
            
            // Kimlik doğrulama - BasicOper kullanarak
            int sector = block / 4;
            String[] authResult = BasicOper.dc_authentication_pass(keyType == 0x60 ? 0 : 4, sector, keyHex).split("\\|", -1);
            return authResult[0].equals("0000");
        } catch (Exception e) {
            appendLog("⚠️ Kimlik doğrulama hatası: " + e.getMessage());
            return false;
        }
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
     * Kart tipine göre bakiye kesme miktarını döndürür
     */
    private BigDecimal getFareByCardType(CardType cardType) {
        if (cardType == null) return TAM_FARE;
        
        switch (cardType) {
            case TAM:
                return TAM_FARE;
            case STUDENT:
                return OGRENCI_FARE;
            case ADULT:
                return YETISKIN_FARE;
            case SENIOR:
                return YASLI_FARE;
            case DISABLED:
                return ENGELLI_FARE;
            case CHILD:
                return COCUK_FARE;
            default:
                return TAM_FARE;
        }
    }
    
    /**
     * BusCard bakiyesini düşürür ve işlem bilgilerini günceller
     * SABİT BİLGİLER KORUNUR: id, cardNumber, fullName, type, status, active, expiryDate, visaCompleted
     */
    private BusCard deductBalanceFromCard(BusCard busCard) {
        if (busCard == null) return null;
        
        // Kart tipine göre ücret belirle
        BigDecimal fare = getFareByCardType(busCard.getType());
        
        // Mevcut bakiye kontrolü
        BigDecimal currentBalance = busCard.getBalance() != null ? busCard.getBalance() : BigDecimal.ZERO;
        
        // UI'yi güncelle
        runOnUiThread(() -> {
            tvCardHolderName.setText(busCard.getFullName() != null ? busCard.getFullName() : "Bilinmiyor");
            tvCardType.setText(busCard.getType() != null ? busCard.getType().getDisplayName() : "Bilinmiyor");
            tvCurrentBalance.setText(currentBalance + " TL");
            tvDeductedAmount.setText("-");
            tvRemainingBalance.setText("-");
        });
        
        if (currentBalance.compareTo(fare) < 0) {
            appendBalanceLog("❌ YETERSİZ BAKİYE!");
            appendBalanceLog("💰 Mevcut: " + currentBalance + " TL");
            appendBalanceLog("💳 Gerekli: " + fare + " TL");
            appendBalanceLog("🚫 İşlem iptal edildi!");
            
            // UI'yi güncelle
            runOnUiThread(() -> {
                tvDeductedAmount.setText("YETERSİZ BAKİYE");
                tvDeductedAmount.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
                tvRemainingBalance.setText(currentBalance + " TL");
                tvRemainingBalance.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
            });
            
            return busCard; // Bakiye yetersizse değişiklik yapma
        }
        
        // SADECE İŞLEM BİLGİLERİNİ GÜNCELLE - SABİT BİLGİLER KORUNUR
        BigDecimal newBalance = currentBalance.subtract(fare);
        busCard.setBalance(newBalance);
        
        // İşlem bilgilerini güncelle
        busCard.setLastTransactionAmount(fare);
        busCard.setLastTransactionDate(LocalDate.now());
        busCard.setTransactionCount(busCard.getTransactionCount() + 1);
        
        appendBalanceLog("✅ BAKİYE DÜŞÜRÜLDÜ!");
        appendBalanceLog("💰 Eski Bakiye: " + currentBalance + " TL");
        appendBalanceLog("💳 Kesilen Ücret: " + fare + " TL (" + busCard.getType().getDisplayName() + ")");
        appendBalanceLog("💰 Yeni Bakiye: " + newBalance + " TL");
        appendBalanceLog("🔢 Toplam İşlem: " + busCard.getTransactionCount());
        appendBalanceLog("📅 İşlem Tarihi: " + LocalDate.now());
        appendBalanceLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        // UI'yi güncelle
        runOnUiThread(() -> {
            tvDeductedAmount.setText("-" + fare + " TL");
            tvDeductedAmount.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
            tvRemainingBalance.setText(newBalance + " TL");
            tvRemainingBalance.setTextColor(getResources().getColor(android.R.color.holo_blue_dark));
        });
        
        return busCard;
    }
    
    /**
     * Sadece bakiye kesme işlemi için özel log metodu
     */
    private void appendBalanceLog(String message) {
        runOnUiThread(() -> {
            String timestamp = java.text.DateFormat.getTimeInstance().format(new java.util.Date());
            String logMessage = "[" + timestamp + "] " + message + "\n";
            tv.append(logMessage);
            
            // Scroll to bottom
            tv.post(() -> {
                int line = tv.getLineCount();
                if (line > 0) {
                    int offset = tv.getLineCount() * tv.getLineHeight();
                    tv.scrollTo(0, offset - tv.getHeight() + tv.getLineHeight());
                }
            });
        });
    }
    
    /**
     * Güncellenmiş BusCard verisini karta yazar
     */
    private boolean writeUpdatedCardToMifare(BusCard updatedBusCard) {
        try {
            appendLog("📝 Güncellenmiş veri karta yazılıyor...");
            
            // BusCard'ı şifrele
            byte[] encryptedData = AESEncryption.encryptBusCardForCard(updatedBusCard);
            
            // MIFARE Classic 1K parametreleri
            final int START_BLOCK = 4;
            final int MAX_BLOCKS_ALLOWED = 45;
            
            // Blok sayısı kontrolü
            int blocksNeeded = (int)Math.ceil(encryptedData.length / 16.0);
            if (blocksNeeded > MAX_BLOCKS_ALLOWED) {
                appendLog("❌ Hata: " + blocksNeeded + " blok gerekiyor; maksimum " + MAX_BLOCKS_ALLOWED);
                return false;
            }
            
            appendLog("🔢 Gerekli blok sayısı: " + blocksNeeded);
            
            // MIFARE Classic karta yaz
            writePayloadToMifareClassic(encryptedData, START_BLOCK);
            
            appendLog("✅ Güncellenmiş veri başarıyla karta yazıldı!");
            return true;
            
        } catch (Exception e) {
            appendLog("❌ Kart yazma hatası: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * MIFARE Classic karta payload yazar
     */
    private void writePayloadToMifareClassic(byte[] fullPayload, int startBlock) throws Exception {
        appendLog("📀 MIFARE Classic 1K karta veri yazılıyor...");

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
                        appendLog("🔑 Sektör " + sector + " Key A ile doğrulandı (" + bytesToHex(key) + ")");
                        authOK = true;
                        break;
                    } else if (authenticateSector(currentBlock, key, (byte)0x61)) {
                        appendLog("🔑 Sektör " + sector + " Key B ile doğrulandı (" + bytesToHex(key) + ")");
                        authOK = true;
                        break;
                    }
                }

                if (!authOK) {
                    appendLog("⚠️ Sektör " + sector + " kimlik doğrulama başarısız, atlanıyor...");
                    // Bu sektörü atla ve bir sonrakine geç
                    currentBlock = ((sector + 1) * 4);
                    continue;
                }
            }

            if (blockInSector == 3) {
                appendLog("⏭️ Trailer blok (blok " + currentBlock + ") atlandı.");
                currentBlock++;
                continue;
            }

            byte[] blockData = new byte[16];
            int toCopy = Math.min(16, fullPayload.length - index);
            System.arraycopy(fullPayload, index, blockData, 0, toCopy);

            // Bloku yaz
            String[] writeResult = BasicOper.dc_write_hex(currentBlock, bytesToHex(blockData).replace(" ", "")).split("\\|", -1);
            if (writeResult[0].equals("0000")) {
                appendLog("✓ Blok " + currentBlock + " yazıldı (" + toCopy + " byte)");
            } else {
                appendLog("❌ Blok " + currentBlock + " yazılamadı (SW=" + writeResult[0] + ")");
                throw new Exception("Blok yazma hatası: " + writeResult[0]);
            }

            index += toCopy;
            currentBlock++;
            // Delay kaldırıldı - hızlandırma için
        }

        appendLog("✅ Yazma işlemi tamamlandı!");
    }
    
    /**
     * MIFARE Classic karttan BusCard verisi okur ve çözer
     */
    private BusCard readBusCardFromCard(byte[] cardData) throws Exception {
        if (cardData == null || cardData.length < 2) {
            throw new Exception("Kart verisi çok kısa veya boş! Uzunluk: " + (cardData != null ? cardData.length : 0));
        }
        
        appendLog("📖 MIFARE Classic karttan BusCard verisi okunuyor...");
        appendLog("📊 Toplam veri uzunluğu: " + cardData.length + " byte");
        
        // AESEncryption ile çöz
        BusCard busCard = AESEncryption.decryptCardDataToBusCard(cardData);
        busCard.setRawData(new String(cardData, "UTF-8"));
        busCard.setDecryptedData(cardData);
        
        appendLog("✅ BusCard verisi başarıyla okundu ve çözüldü!");
        return busCard;
    }
    
    
    /**
     * Çözülen string'i BusCard nesnesine dönüştürür
     */
    private BusCard parseBusCardFromString(String decryptedContent) {
        BusCard busCard = new BusCard();
        
        try {
            // Basit parsing - gerçek uygulamada daha karmaşık olabilir
            String[] lines = decryptedContent.split("\n");
            
            for (String line : lines) {
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length == 2) {
                        String key = parts[0].trim().toLowerCase();
                        String value = parts[1].trim();
                        
                        switch (key) {
                            case "kart numarası":
                            case "cardnumber":
                                busCard.setCardNumber(value);
                                break;
                            case "ad soyad":
                            case "fullname":
                                busCard.setFullName(value);
                                break;
                            case "kart tipi":
                            case "type":
                                busCard.setType(parseCardType(value));
                                break;
                            case "durum":
                            case "status":
                                busCard.setStatus(parseCardStatus(value));
                                break;
                            case "bakiye":
                            case "balance":
                                busCard.setBalance(parseBigDecimal(value));
                                break;
                            case "aktif":
                            case "active":
                                busCard.setActive(parseBoolean(value));
                                break;
                            case "çıkış tarihi":
                            case "issuedate":
                                busCard.setIssueDate(parseLocalDate(value));
                                break;
                            case "son kullanma":
                            case "expirydate":
                                busCard.setExpiryDate(parseLocalDate(value));
                                break;
                            case "vize tamamlandı":
                            case "visacompleted":
                                busCard.setVisaCompleted(parseBoolean(value));
                                break;
                            case "son işlem tutarı":
                            case "lasttransactionamount":
                                busCard.setLastTransactionAmount(parseBigDecimal(value));
                                break;
                            case "son işlem tarihi":
                            case "lasttransactiondate":
                                busCard.setLastTransactionDate(parseLocalDate(value));
                                break;
                            case "işlem sayısı":
                            case "transactioncount":
                                busCard.setTransactionCount(parseInt(value));
                                break;
                        }
                    }
                }
            }
            
            // Eğer hiçbir veri parse edilemediyse, ham veriyi göster
            if (busCard.getCardNumber() == null && busCard.getFullName() == null) {
                busCard.setCardNumber("Parse Edilemedi");
                busCard.setFullName("Ham Veri: " + decryptedContent.substring(0, Math.min(50, decryptedContent.length())));
            }
            
        } catch (Exception e) {
            appendLog("⚠️ BusCard parsing hatası: " + e.getMessage());
            busCard.setCardNumber("Parse Hatası");
            busCard.setFullName("Hata: " + e.getMessage());
        }
        
        return busCard;
    }
    
    private CardType parseCardType(String value) {
        if (value == null) return CardType.UNKNOWN;
        String lower = value.toLowerCase();
        if (lower.contains("öğrenci") || lower.contains("student")) return CardType.STUDENT;
        if (lower.contains("öğretmen") || lower.contains("teacher")) return CardType.TEACHER;
        if (lower.contains("personel") || lower.contains("staff")) return CardType.STAFF;
        if (lower.contains("normal") || lower.contains("regular")) return CardType.REGULAR;
        if (lower.contains("yaşlı") || lower.contains("senior")) return CardType.SENIOR;
        if (lower.contains("engelli") || lower.contains("disabled")) return CardType.DISABLED;
        return CardType.UNKNOWN;
    }
    
    private CardStatus parseCardStatus(String value) {
        if (value == null) return CardStatus.UNKNOWN;
        String lower = value.toLowerCase();
        if (lower.contains("aktif") || lower.contains("active")) return CardStatus.ACTIVE;
        if (lower.contains("pasif") || lower.contains("inactive")) return CardStatus.INACTIVE;
        if (lower.contains("bloklu") || lower.contains("blocked")) return CardStatus.BLOCKED;
        if (lower.contains("süresi dolmuş") || lower.contains("expired")) return CardStatus.EXPIRED;
        if (lower.contains("kayıp") || lower.contains("lost")) return CardStatus.LOST;
        if (lower.contains("çalıntı") || lower.contains("stolen")) return CardStatus.STOLEN;
        return CardStatus.UNKNOWN;
    }
    
    private BigDecimal parseBigDecimal(String value) {
        try {
            if (value == null || value.trim().isEmpty()) return null;
            return new BigDecimal(value.replaceAll("[^0-9.,]", "").replace(",", "."));
        } catch (Exception e) {
            return null;
        }
    }
    
    private boolean parseBoolean(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase();
        return lower.contains("evet") || lower.contains("yes") || lower.contains("true") || lower.contains("1");
    }
    
    private LocalDate parseLocalDate(String value) {
        try {
            if (value == null || value.trim().isEmpty()) return null;
            // Farklı tarih formatlarını dene
            String[] formats = {"yyyy-MM-dd", "dd/MM/yyyy", "dd.MM.yyyy", "yyyy/MM/dd"};
            for (String format : formats) {
                try {
                    return LocalDate.parse(value, DateTimeFormatter.ofPattern(format));
                } catch (DateTimeParseException ignored) {}
            }
            return null;
            } catch (Exception e) {
            return null;
        }
    }
    
    private int parseInt(String value) {
        try {
            if (value == null || value.trim().isEmpty()) return 0;
            return Integer.parseInt(value.replaceAll("[^0-9]", ""));
        } catch (Exception e) {
            return 0;
        }
    }
    
    
    
    /**
     * Otomatik kart okuma döngüsünü başlatır
     */
    private void startAutoCardReading() {
        isAutoReading = true;
        autoReadThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (isAutoReading) {
                    try {
                        // MIFARE Classic kart algılama
                        int st = detectMifareCard();
                        if (st == 0) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    tvStatus.setText("🔘 Kart algılandı - Okunuyor...");
                                    appendBalanceLog("🔘 KART ALGILANDI - OKUNUYOR...");
                                }
                            });
                            
                            // Kart UID'sini oku
                            String[] resultArr = BasicOper.dc_card_n_hex(DISCOVERY_MODE_ALL_CARD).split("\\|", -1);
                            if (resultArr[0].equals("0000")) {
                                final String cardUid = resultArr[1];
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        tvStatus.setText("✅ Kart okundu - Veri işleniyor...");
                                        appendBalanceLog("🆔 Kart UID: " + cardUid);
                                        appendBalanceLog("✅ MIFARE Classic kart algılandı");
                                    }
                                });
                                
                                // MIFARE Classic karttan veri oku
                                byte[] cardData = readMifareClassicData();
                                if (cardData != null && cardData.length > 0) {
                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            appendBalanceLog("📊 Kart verisi okundu: " + cardData.length + " byte");
                                        }
                                    });

                                    // Şifreli veriyi çöz ve BusCard nesnesine dönüştür
                                    try {
                                        BusCard busCard = readBusCardFromCard(cardData);

                                        runOnUiThread(new Runnable() {
                                            @Override
                                            public void run() {
                                                appendBalanceLog("✅ ŞİFRE ÇÖZME BAŞARILI!");
                                                appendBalanceLog("👤 Ad Soyad: " + (busCard.getFullName() != null ? busCard.getFullName() : "Bilinmiyor"));
                                                appendBalanceLog("🎫 Kart Tipi: " + (busCard.getType() != null ? busCard.getType().getDisplayName() : "Bilinmiyor"));
                                                appendBalanceLog("💰 Mevcut Bakiye: " + (busCard.getBalance() != null ? busCard.getBalance() : "0") + " TL");
                                                appendBalanceLog("🔢 Toplam İşlem: " + busCard.getTransactionCount());
                                            }
                                        });
                                        
                                        // Bakiye kesme ve kart güncelleme işlemi
                                        try {
                                            runOnUiThread(() -> {
                                                tvStatus.setText("💳 Bakiye kesme işlemi...");
                                            });
                                            
                                            appendBalanceLog("💳 BAKİYE KESME İŞLEMİ BAŞLATILIYOR...");
                                            
                                            // Bakiye düşür
                                            BusCard updatedBusCard = deductBalanceFromCard(busCard);
                                            
                                            if (updatedBusCard != null) {
                                                // Güncellenmiş veriyi karta yaz
                                                boolean writeSuccess = writeUpdatedCardToMifare(updatedBusCard);
                                                
                                                if (writeSuccess) {
                                                    runOnUiThread(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            tvStatus.setText("✅ İşlem tamamlandı!");
                                                            appendBalanceLog("🎉 İŞLEM TAMAMLANDI!");
                                                            appendBalanceLog("✅ Kart güncellendi");
                                                            appendBalanceLog("💰 Güncel Bakiye: " + updatedBusCard.getBalance() + " TL");
                                                            appendBalanceLog("🔢 Toplam İşlem: " + updatedBusCard.getTransactionCount());
                                                            appendBalanceLog("📅 Son İşlem: " + updatedBusCard.getLastTransactionDate());
                                                        }
                                                    });
                                                } else {
                                                    runOnUiThread(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            tvStatus.setText("❌ Kart güncelleme hatası!");
                                                            appendBalanceLog("❌ KART GÜNCELLEME HATASI!");
                                                            appendBalanceLog("⚠️ Bakiye düşürüldü ama kart güncellenemedi!");
                                                        }
                                                    });
                                                }
                                            }
                                            
                                        } catch (Exception e) {
                                            runOnUiThread(new Runnable() {
                                                @Override
                                                public void run() {
                                                    tvStatus.setText("❌ Bakiye kesme hatası!");
                                                    appendBalanceLog("❌ BAKİYE KESME HATASI: " + e.getMessage());
                                                }
                                            });
                                        }
                                        
                                    } catch (Exception e) {
                                        runOnUiThread(new Runnable() {
                                            @Override
                                            public void run() {
                                                tvStatus.setText("❌ Şifre çözme hatası!");
                                                appendBalanceLog("❌ Şifre çözme hatası: " + e.getMessage());
                                            }
                                        });
                                    }

                                } else {
                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            tvStatus.setText("❌ Kart verisi okunamadı!");
                                            appendBalanceLog("❌ HATA: Kart verisi okunamadı!");
                                        }
                                    });
                                }
                                
                                // Kart işlemi tamamlandı - anında yeni karta geçiş
                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                        tvStatus.setText("✅ İşlem tamamlandı - Yeni kart bekleniyor...");
                                        appendBalanceLog("✅ Kart işlemi tamamlandı");
                                        appendBalanceLog("🔍 Yeni kart bekleniyor...");
                                        appendBalanceLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                                    }
                                });
                                
                            } else {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        tvStatus.setText("❌ UID okunamadı!");
                                        appendBalanceLog("❌ UID okunamadı!");
                                    }
                                });
                            }
                        }
                        
                        // Delay kaldırıldı - hızlandırma için
                        
                    } catch (Exception e) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvStatus.setText("❌ Okuma hatası!");
                                appendBalanceLog("❌ Otomatik okuma hatası: " + e.getMessage());
                            }
                        });
                        // Delay kaldırıldı - hızlandırma için
                    }
                }
            }
        });
        autoReadThread.start();
    }
    
    /**
     * Otomatik kart okuma döngüsünü durdurur
     */
    private void stopAutoCardReading() {
        isAutoReading = false;
        if (autoReadThread != null) {
            autoReadThread.interrupt();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        if(!isReaderOpened()){
                return false;
            }
        return super.onCreateOptionsMenu(menu);
    }
    
    @Override
    public void onDestroy(){
        Log.i(TAG,"======onDestroy ==========");
        // Otomatik okuma döngüsünü durdur
        stopAutoCardReading();
        // Port kapat
        closeReader();
        super.onDestroy();
    }
}