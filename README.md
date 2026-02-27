# P18 NFC Kart Okuyucu / Validator

DeCard P18 donanımı ile çalışan Android tabanlı NFC akıllı kart okuyucu ve toplu taşıma kartı doğrulama uygulaması.

## Özellikler

- **NFC / Akıllı kart desteği**: MIFARE DESFire EV1/EV3, MIFARE Plus, MIFARE UltraLight
- **Toplu taşıma kartı okuma**: Kart numarası, bakiye, kart sahibi, kart tipi ve durum bilgisi
- **Şifreleme**: AES ile kart verisi şifreleme/çözme
- **DESFire işlemleri**: Uygulama oluşturma, dosya oluşturma, PICC formatlama, kişiselleştirme
- **Test ortamı**: DESFire EV3 ve DESFire Light test ortamı kurulumu
- **SAM AV2**: Güvenli erişim modülü desteği

## Gereksinimler

- **Android**: minSdk 23, targetSdk 29 (compileSdk 33)
- **NFC**: Cihazda NFC donanımı gerekli
- **DeCard P18**: Opsiyonel; P18 okuyucu ile tam işlevsellik

## Kurulum

1. Projeyi klonlayın veya indirin.
2. Android Studio ile açın.
3. `app/libs` klasörüne gerekli DeCard JAR/AAR kütüphanelerini ekleyin (varsa).
4. Projeyi derleyin:
   ```bash
   ./gradlew assembleDebug
   ```
   veya Android Studio’dan **Run** ile çalıştırın.

Derlenen APK adı: `P18-{variant}-v{versionName}.apk` (örn. `P18-debug-v1.2.apk`).

## Proje Yapısı

| Paket / Klasör | Açıklama |
|----------------|----------|
| `com.decard.exampleSrc` | Ana aktiviteler, okuyucu sürücüleri (P18 DESFire, MIFARE Plus, SAM) |
| `com.decard.exampleSrc.desfire` | DESFire EV1/EV3 model, şifreleme, komut katmanı |
| `com.decard.exampleSrc.ui` | DESFire Main, Format, Personalize, Setup Test/Light ekranları |
| `com.example.nfcreader` | BusCard, CardType, CardStatus, AESEncryption (kart doğrulama) |

## Bağımlılıklar

- AndroidX (AppCompat, ConstraintLayout, Material)
- `androidx.security:security-crypto`
- `org.slf4j:slf4j-android`
- Yerel JAR’lar: `app/libs` içindeki DeCard kütüphaneleri

## Sürüm

- **versionName**: 1.2  
- **versionCode**: 1  

## Lisans

Proje sahibi tarafından belirtilmediği sürece bu depodaki kod örnek ve referans amaçlıdır.
