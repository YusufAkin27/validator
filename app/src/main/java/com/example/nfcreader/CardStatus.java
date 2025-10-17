package com.example.nfcreader;

public enum CardStatus {
    ACTIVE("Aktif"),
    INACTIVE("Pasif"),
    BLOCKED("Bloklu"),
    LOST("Kayıp"),
    EXPIRED("Süresi Dolmuş"),
    AWAITING_VISA("Vize Bekliyor"),
    SUSPENDED("Askıda"),
    STOLEN("Çalıntı"),
    UNKNOWN("Bilinmeyen");
    
    private final String displayName;
    
    CardStatus(String displayName) {
        this.displayName = displayName;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    @Override
    public String toString() {
        return displayName;
    }
}
