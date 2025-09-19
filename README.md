# 🔐 File Encryptor / Decryptor

โปรเจกต์นี้เป็นเว็บแอปพลิเคชัน **File Encryptor / Decryptor** ใช้ Flask และ PyCryptodome เพื่อ **เข้ารหัสและถอดรหัสไฟล์ทุกชนิด** เช่น รูปภาพ, วิดีโอ, เสียง, เอกสาร และไฟล์บีบอัด

---

## 💻 คุณสมบัติ

- รองรับไฟล์ทุกชนิด: `.jpg, .png, .mp3, .wav, .mp4, .mkv, .txt, .pdf, .docx, .zip` และอื่น ๆ
- เข้ารหัสไฟล์ด้วย AES-256 CBC
- ถอดรหัสไฟล์ด้วยรหัสผ่านเดียวกับที่ใช้เข้ารหัส
- แจ้งเตือนเมื่อรหัสผ่านไม่ถูกต้องหรือไฟล์เสียหาย
- ใช้งานง่ายผ่านเว็บอินเตอร์เฟส

---

## ⚙️ การติดตั้ง

1. **ติดตั้ง Python 3.9+**  
   ตรวจสอบเวอร์ชัน:
   ```bash
   python3 --version

2.	โคลนโปรเจกต์นี้
    git clone <your-repo-url>
    cd <your-project-folder>

3.	สร้าง Virtual Environment และติดตั้ง Dependencies
    python3 -m venv .venv

    source .venv/bin/activate       # macOS / Linux
    .venv\Scripts\activate          # Windows

    pip install -r requirements.txt

---

## 🚀 การใช้งาน
   ```bash
    python term_project.py