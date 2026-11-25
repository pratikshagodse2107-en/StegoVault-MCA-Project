# 🛡️ STEGO VAULT — Hide in Plain Sight.
**A Python-Based Secure Digital Image Steganography & Cryptanalysis System (MCA Project)**

## 📌 Overview
STEGO VAULT combines **AES-256-GCM authenticated encryption**, **PBKDF2-SHA256 key derivation**, **Zlib lossless compression**, and **Password-Seeded Random Pixel LSB Steganography** to conceal confidential text (including Marathi/Unicode) and files (PDF, DOCX, TXT, ZIP) inside PNG images without visible distortion.

## ✨ Key Features
1. **PBKDF2 & SQLite Authentication (`db_manager.py`):** Salted password hashing and per-user persistent audit logs.
2. **Password-Seeded Random LSB Embedding (`stego_engine.py`):** Eliminates sequential pixel patterns and plaintext signatures to resist statistical steganalysis.
3. **File & Unicode Support:** Compresses and embeds PDFs, documents, and multi-byte UTF-8 Marathi text with real-time byte capacity tracking.
4. **Quality & Cryptographic Analysis (`analysis_engine.py`):** Computes **PSNR**, **MSE**, **SSIM**, **255x Pixel Difference Maps**, **RGB Histograms**, and **SHA-256 Hashes**.
5. **Statistical Steganalysis Lab:** Visualizes the **LSB Bit-Plane** and executes a **Pair-of-Values Chi-Square ($\chi^2$) Test**.

## 🚀 Setup & Installation
```bash
pip install -r requirements.txt
python -m streamlit run main.py
```

## 🧪 Running Automated Unit Tests
```bash
pytest -v
```
