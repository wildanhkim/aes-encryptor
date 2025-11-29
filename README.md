# 🔐 AES-256 File Encryptor (GUI) — Wild

Aplikasi enkripsi & dekripsi file berbasis **AES-256-GCM** dengan **GUI Tkinter**, didesain agar mudah digunakan di **Windows, Linux, dan macOS**.  
Password dikelola menggunakan **PBKDF2-HMAC-SHA256** sehingga keamanan tetap terjamin.

Aplikasi ini cocok untuk:
- Mengenkripsi file pribadi (PDF, ZIP, foto, dokumen)
- Melindungi password atau data sensitif
- Belajar kriptografi modern (AES-GCM + PBKDF2)
- Penggunaan lintas platform (Windows & Linux)

---

## ✨ Fitur Utama

✔ **AES-256-GCM** (Authenticated Encryption – aman + ada tag integritas)  
✔ **Password-based key** (PBKDF2 SHA-256, 200.000 iterasi)  
✔ **GUI modern** dengan Tkinter  
✔ **Enkripsi otomatis → file.enc**  
✔ **Dekripsi otomatis untuk file .enc**  
✔ **Deteksi password salah / file rusak**  
✔ Cross-platform: Windows, Linux, macOS  
✔ Bisa dibuat menjadi **.exe** (PyInstaller)

---

## 📦 Instalasi

### 1. Clone Repo

```bash
git clone https://github.com/<USERNAME>/<REPO>.git
cd <REPO>
