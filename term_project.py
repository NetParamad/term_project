from flask import Flask, request, render_template, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os
import io

app = Flask(__name__)

def derive_key(password: str, salt: bytes, key_len=32):
    return PBKDF2(password, salt, dkLen=key_len, count=100_000)

def encrypt_file(file_bytes, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file_bytes, AES.block_size))
    return salt + iv + encrypted_data

def decrypt_file(file_bytes, password):
    salt, iv, encrypted_data = file_bytes[:16], file_bytes[16:32], file_bytes[32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        file = request.files["file"]
        password = request.form["password"]
        mode = request.form["mode"]

        file_bytes = file.read()
        try:
            if mode == "encrypt":
                result = encrypt_file(file_bytes, password)
                out_filename = file.filename + ".enc"
            else:
                # ใช้ try...except เพื่อจับ padding error
                try:
                    result = decrypt_file(file_bytes, password)
                    out_filename = os.path.splitext(file.filename)[0]  # ตัด .enc
                except ValueError:
                    message = "❌ รหัสผ่านไม่ถูกต้องหรือไฟล์เสียหาย"
                    return f'''
                    <h2>🔐 File Encryptor / Decryptor</h2>
                    <p style="color:red;">{message}</p>
                    <form method="post" enctype="multipart/form-data">
                        <label>เลือกไฟล์: <input type="file" name="file" required></label><br><br>
                        <label>รหัสผ่าน: <input type="password" name="password" required></label><br><br>
                        <label>
                            <input type="radio" name="mode" value="encrypt" checked> เข้ารหัส
                            <input type="radio" name="mode" value="decrypt"> ถอดรหัส
                        </label><br><br>
                        <button type="submit">🚀 เริ่มทำงาน</button>
                    </form>
                    '''
            return send_file(
                io.BytesIO(result),
                as_attachment=True,
                download_name=out_filename
            )
        except Exception as e:
            message = f"เกิดข้อผิดพลาด: {e}"

    return f'''
    <h2>🔐 File Encryptor / Decryptor</h2>
    <p style="color:red;">{message}</p>
    <p>รองรับไฟล์ทุกชนิด: รูปภาพ (.jpg, .png), เสียง (.mp3, .wav), วิดีโอ (.mp4, .mkv), ข้อความ/เอกสาร (.txt, .pdf, .docx), ไฟล์บีบอัด (.zip) และอื่นๆ</p>
    <form method="post" enctype="multipart/form-data">
        <label>เลือกไฟล์: <input type="file" name="file" required></label><br><br>
        <label>รหัสผ่าน: <input type="password" name="password" required></label><br><br>
        <label>
            <input type="radio" name="mode" value="encrypt" checked> เข้ารหัส
            <input type="radio" name="mode" value="decrypt"> ถอดรหัส
        </label><br><br>
        <button type="submit">🚀 เริ่มทำงาน</button>
    </form>
    '''
if __name__ == "__main__":
    app.run(debug=True)