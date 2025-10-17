package com.example.nfcreader;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.paint.Color;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

public class ReadCardController extends BaseController {
    @FXML
    private TextField cardUidField;
    
    @FXML
    private TextField cardTypeField;
    
    @FXML
    private Button readCardButton;
    
    @FXML
    private Label statusLabel;
    
    @FXML
    private TextArea dataArea;
    
    @FXML
    private Button backButton;
    
    private NfcCardReader nfcReader;
    private ObjectMapper objectMapper;
    
    @FXML
    public void initialize() {
        objectMapper = new ObjectMapper();
        
        // NFC okuyucuyu başlat
        try {
            nfcReader = new NfcCardReader();
            statusLabel.setText("NFC cihazı hazır. Kartı okutun.");
            statusLabel.setTextFill(Color.GREEN);
        } catch (CardException e) {
            statusLabel.setText("NFC cihazı bulunamadı: " + e.getMessage());
            statusLabel.setTextFill(Color.RED);
            readCardButton.setDisable(true);
        }
    }
    
    @FXML
    protected void onReadCardButtonClick() {
        if (nfcReader == null) {
            statusLabel.setText("NFC cihazı bulunamadı!");
            statusLabel.setTextFill(Color.RED);
            return;
        }
        
        readCardButton.setDisable(true);
        statusLabel.setText("Kart okunuyor... Lütfen kartı cihaza yaklaştırın.");
        statusLabel.setTextFill(Color.BLUE);
        
        // Kart okuma işlemini ayrı thread'de çalıştır
        new Thread(() -> {
            try {
                // Kartı bekle ve bağlan
                nfcReader.waitForCardAndConnect();
                
                // UID oku
                String uid = nfcReader.readCardUid();
                String cardType = nfcReader.getCardType();
                
                Platform.runLater(() -> {
                    cardUidField.setText(uid);
                    cardTypeField.setText(cardType);
                    statusLabel.setText("Kart UID okundu: " + uid);
                    statusLabel.setTextFill(Color.GREEN);
                });
                
                // Kart verilerini oku (eğer varsa)
                try {
                    readCardData();
                } catch (Exception e) {
                    Platform.runLater(() -> {
                        dataArea.setText("Kart verisi okunamadı: " + e.getMessage());
                    });
                }
                
                // Kartın çıkarılmasını bekle
                nfcReader.waitForCardRemoval();
                
                Platform.runLater(() -> {
                    statusLabel.setText("Kart okuma tamamlandı. Yeni kart okutabilirsiniz.");
                    statusLabel.setTextFill(Color.GREEN);
                    readCardButton.setDisable(false);
                });
                
            } catch (Exception e) {
                Platform.runLater(() -> {
                    statusLabel.setText("Kart okunamadı: " + e.getMessage());
                    statusLabel.setTextFill(Color.RED);
                    readCardButton.setDisable(false);
                });
            }
        }).start();
    }
    
    /**
     * Kart verilerini okur ve gösterir
     */
    private void readCardData() throws CardException {
        try {
            // Önce MIFARE Classic BusCard okuma deneyelim
            readMifareClassicBusCardData();
            
        } catch (Exception e) {
            // MIFARE Classic okuma başarısız olursa Ultralight deneyelim
            try {
                readUltralightCardData();
                
            } catch (Exception e2) {
                // Ultralight okuma da başarısız olursa basit okuma deneyelim
                try {
                    readSimpleCardData();
                } catch (Exception e3) {
                    Platform.runLater(() -> {
                        dataArea.setText("❌ Veri okuma hatası: " + e.getMessage() + "\n\n" +
                                       "💡 Bu kart henüz veri yazılmamış olabilir veya farklı bir formatta olabilir.");
                    });
                }
            }
        }
    }
    
    /**
     * MIFARE Classic BusCard verisi okuma (şifreli veri)
     */
    private void readMifareClassicBusCardData() throws CardException {
        try {
            BusCard busCard = nfcReader.readBusCardFromCard();
            
            Platform.runLater(() -> {
                StringBuilder cardInfo = new StringBuilder();
                cardInfo.append("🔓 Şifreli BusCard Verisi Çözüldü:\n\n");
                cardInfo.append("🆔 ID: ").append(busCard.getId() != null ? busCard.getId() : "N/A").append("\n");
                cardInfo.append("📋 Kart Numarası: ").append(busCard.getCardNumber()).append("\n");
                cardInfo.append("📊 Kart Tipi: ").append(busCard.getType() != null ? busCard.getType().getDisplayName() : "N/A").append("\n");
                cardInfo.append("📊 Kart Durumu: ").append(busCard.getStatus() != null ? busCard.getStatus().getDisplayName() : "N/A").append("\n");
                cardInfo.append("👤 Ad Soyad: ").append(busCard.getFullName()).append("\n");
                cardInfo.append("💰 Bakiye: ").append(busCard.getBalance()).append(" TL\n");
                cardInfo.append("✅ Aktif: ").append(busCard.isActive() ? "Evet" : "Hayır").append("\n");
                cardInfo.append("📅 Çıkış Tarihi: ").append(busCard.getIssueDate() != null ? busCard.getIssueDate().toString() : "N/A").append("\n");
                cardInfo.append("📅 Son Kullanma Tarihi: ").append(busCard.getExpiryDate() != null ? busCard.getExpiryDate().toString() : "N/A").append("\n");
                cardInfo.append("🛂 Vize Tamamlandı: ").append(busCard.isVisaCompleted() ? "Evet" : "Hayır").append("\n");
                cardInfo.append("💳 Son İşlem Tutarı: ").append(busCard.getLastTransactionAmount()).append(" TL\n");
                cardInfo.append("📅 Son İşlem Tarihi: ").append(busCard.getLastTransactionDate() != null ? busCard.getLastTransactionDate().toString() : "N/A").append("\n");
                cardInfo.append("🔢 İşlem Sayısı: ").append(busCard.getTransactionCount()).append("\n");
                
                dataArea.setText(cardInfo.toString());
            });
            
        } catch (Exception e) {
            throw new CardException("MIFARE Classic BusCard veri okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Ultralight kart verisi okuma (şifreli veri)
     */
    private void readUltralightCardData() throws CardException {
        try {
            String decryptedContent = nfcReader.readUltralightCardData();
            
            Platform.runLater(() -> {
                dataArea.setText("🔓 Şifreli Kart Verisi Çözüldü:\n\n" + decryptedContent);
            });
            
        } catch (Exception e) {
            throw new CardException("Ultralight veri okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Basit kart verisi okuma (şifreleme olmadan)
     */
    private void readSimpleCardData() throws CardException {
        try {
            // Varsayılan anahtarla kimlik doğrulama
            byte[] defaultKey = {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
            
            // Sektör 4'ten başlayarak veri okumaya çalış
            StringBuilder cardData = new StringBuilder();
            boolean dataFound = false;
            
            for (int sector = 4; sector <= 6; sector++) {
                for (int block = 0; block < 3; block++) { // Trailer bloğu hariç
                    try {
                        byte[] blockData = readBlockWithKey(sector, block, defaultKey);
                        if (blockData != null && !isEmptyBlock(blockData)) {
                            String blockString = new String(blockData, java.nio.charset.StandardCharsets.UTF_8).trim();
                            if (!blockString.isEmpty()) {
                                cardData.append("Sektör ").append(sector).append(", Blok ").append(block).append(": ");
                                cardData.append(blockString).append("\n");
                                dataFound = true;
                            }
                        }
                    } catch (Exception e) {
                        // Bu blok okunamadı, devam et
                        continue;
                    }
                }
            }
            
            final boolean finalDataFound = dataFound;
            final String finalCardData = cardData.toString();
            
            Platform.runLater(() -> {
                if (finalDataFound) {
                    dataArea.setText("📦 Okunan Kart Verisi:\n\n" + finalCardData);
                } else {
                    dataArea.setText("📦 Kart verisi bulunamadı.\n\n" +
                                   "💡 Bu kart henüz veri yazılmamış olabilir.\n" +
                                   "💡 Kart kaydetme sayfasından veri yazabilirsiniz.");
                }
            });
            
        } catch (Exception e) {
            throw new CardException("Basit veri okuma hatası: " + e.getMessage());
        }
    }
    
    /**
     * Belirtilen anahtarla blok okur
     */
    private byte[] readBlockWithKey(int sector, int block, byte[] key) throws CardException {
        try {
            // Anahtarı yükle
            byte[] loadKeyCmd = new byte[11];
            loadKeyCmd[0] = (byte)0xFF;
            loadKeyCmd[1] = (byte)0x82;
            loadKeyCmd[2] = 0x00;
            loadKeyCmd[3] = 0x00;
            loadKeyCmd[4] = 0x06;
            System.arraycopy(key, 0, loadKeyCmd, 5, 6);
            
            ResponseAPDU response = nfcReader.channel.transmit(new CommandAPDU(loadKeyCmd));
            if (response.getSW() != 0x9000) {
                return null;
            }
            
            // Kimlik doğrulama
            byte[] authCmd = {
                (byte)0xFF, (byte)0x86, 0x00, 0x00, 0x05,
                0x01, 0x00, (byte)(sector * 4 + block), 0x60, 0x00
            };
            
            response = nfcReader.channel.transmit(new CommandAPDU(authCmd));
            if (response.getSW() != 0x9000) {
                return null;
            }
            
            // Bloku oku
            byte[] readCmd = {
                (byte)0xFF, (byte)0xB0, 0x00, (byte)(sector * 4 + block), 0x10
            };
            
            response = nfcReader.channel.transmit(new CommandAPDU(readCmd));
            if (response.getSW() == 0x9000) {
                return response.getData();
            }
            
            return null;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Blokun boş olup olmadığını kontrol eder
     */
    private boolean isEmptyBlock(byte[] blockData) {
        if (blockData == null) return true;
        
        for (byte b : blockData) {
            if (b != 0x00 && b != (byte)0xFF) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Controller kapatılırken NFC okuyucuyu temizle
     */
    public void cleanup() {
        if (nfcReader != null) {
            nfcReader.close();
        }
    }
}
