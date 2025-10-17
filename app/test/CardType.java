package com.example.nfcreader;

public enum CardType {
    TAM("Tam"),
    STUDENT("Öğrenci"),
    ADULT("Yetişkin"),
    SENIOR("Yaşlı"),
    DISABLED("Engelli"),
    CHILD("Çocuk");
    
    private final String displayName;
    
    CardType(String displayName) {
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
