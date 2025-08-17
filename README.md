# 🔥 RFI / LFI Tester Scanner

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?logo=windows)
![Status](https://img.shields.io/badge/Status-Stable-success)

> 🕷️ Gelişmiş **RFI / LFI Scanner**  
> Parametreleri otomatik keşfeder, akıllı payloadlarla test eder, sonuçları renkli raporlar.  
> Yazarı: **RavenGod**

---

## 📸 Ekran Görüntüsü

![Screenshot](Ekran%20görüntüsü%202025-08-17%20141633.png)

---

## ✨ Özellikler
- 🌐 **Akıllı crawl** → siteleri gezip parametre toplar  
- 📝 **Form analizi** → input/select/textarea parametreleri bulur  
- ⚔️ **Gelişmiş LFI payloadları** → `/etc/passwd`, Windows `hosts`, PHP wrapper testleri  
- 🚀 **RFI payloadları** → HTTP, FTP, php://, data://, expect://, zip://, phar:// testleri  
- 🎯 **Akıllı parametre seçimi** → file, page, id, include gibi yüzlerce parametreyi dener  
- 📊 **Renkli istatistikler** → payload sonucu, response boyutu, sample output gösterir  
- ⏱️ **Hızlı tarama** → multi-layer crawl + random payload seçimi ile optimize  

---

## ⚙️ Kurulum

```bash
git clone https://github.com/Raven-Of-God/RFİ-Vulnerable-Scanner
cd RFİ-Vulnerable-Scanner
python3 lfi.py
