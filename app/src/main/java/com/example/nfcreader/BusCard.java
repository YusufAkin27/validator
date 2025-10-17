package com.example.nfcreader;

import java.math.BigDecimal;
import java.time.LocalDate;

public class BusCard {
    private Long id;
    private String cardNumber;
    private String fullName;
    private CardType type;
    private CardStatus status;
    private BigDecimal balance;
    private boolean active;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private boolean visaCompleted;
    private BigDecimal lastTransactionAmount;
    private LocalDate lastTransactionDate;
    private int transactionCount;
    private String rawData;
    private byte[] decryptedData;

    // Constructor
    public BusCard(Long id, String cardNumber, String fullName, CardType type, CardStatus status,
                   BigDecimal balance, boolean active, LocalDate issueDate, LocalDate expiryDate,
                   boolean visaCompleted, BigDecimal lastTransactionAmount, LocalDate lastTransactionDate, int transactionCount) {
        this.id = id;
        this.cardNumber = cardNumber;
        this.fullName = fullName;
        this.type = type;
        this.status = status;
        this.balance = balance;
        this.active = active;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.visaCompleted = visaCompleted;
        this.lastTransactionAmount = lastTransactionAmount;
        this.lastTransactionDate = lastTransactionDate;
        this.transactionCount = transactionCount;
    }
    
    // Default constructor
    public BusCard() {
    }

    // Getters
    public Long getId() { return id; }
    public String getCardNumber() { return cardNumber; }
    public String getFullName() { return fullName; }
    public CardType getType() { return type; }
    public CardStatus getStatus() { return status; }
    public BigDecimal getBalance() { return balance; }
    public boolean isActive() { return active; }
    public LocalDate getIssueDate() { return issueDate; }
    public LocalDate getExpiryDate() { return expiryDate; }
    public boolean isVisaCompleted() { return visaCompleted; }
    public BigDecimal getLastTransactionAmount() { return lastTransactionAmount; }
    public LocalDate getLastTransactionDate() { return lastTransactionDate; }
    public int getTransactionCount() { return transactionCount; }
    public String getRawData() { return rawData; }
    public byte[] getDecryptedData() { return decryptedData; }

    // Setters
    public void setId(Long id) { this.id = id; }
    public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public void setType(CardType type) { this.type = type; }
    public void setStatus(CardStatus status) { this.status = status; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }
    public void setActive(boolean active) { this.active = active; }
    public void setIssueDate(LocalDate issueDate) { this.issueDate = issueDate; }
    public void setExpiryDate(LocalDate expiryDate) { this.expiryDate = expiryDate; }
    public void setVisaCompleted(boolean visaCompleted) { this.visaCompleted = visaCompleted; }
    public void setLastTransactionAmount(BigDecimal lastTransactionAmount) { this.lastTransactionAmount = lastTransactionAmount; }
    public void setLastTransactionDate(LocalDate lastTransactionDate) { this.lastTransactionDate = lastTransactionDate; }
    public void setTransactionCount(int transactionCount) { this.transactionCount = transactionCount; }
    public void setRawData(String rawData) { this.rawData = rawData; }
    public void setDecryptedData(byte[] decryptedData) { this.decryptedData = decryptedData; }

    @Override
    public String toString() {
        return "BusCard{" +
                "id=" + id +
                ", cardNumber='" + cardNumber + '\'' +
                ", fullName='" + fullName + '\'' +
                ", type=" + type +
                ", status=" + status +
                ", balance=" + balance +
                ", active=" + active +
                ", issueDate=" + issueDate +
                ", expiryDate=" + expiryDate +
                ", visaCompleted=" + visaCompleted +
                ", lastTransactionAmount=" + lastTransactionAmount +
                ", lastTransactionDate=" + lastTransactionDate +
                ", transactionCount=" + transactionCount +
                '}';
    }
}
