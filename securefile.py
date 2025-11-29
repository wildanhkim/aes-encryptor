#!/usr/bin/env python3
"""
securefile_gui.py
AES-256-GCM File Encrypter/Decrypter (GUI)
Versi Windows + Linux (Wildan Edition)

Fitur:
 - Enkripsi AES-256-GCM (modern, aman)
 - Dekripsi dengan validasi tag (cegah password salah)
 - Password-based key (PBKDF2-HMAC-SHA256)
 - File ".enc" otomatis
 - GUI Tkinter lengkap (button, notif, status)
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Konstanta format file terenkripsi ----
MAGIC = b"WCF1"        # penanda file enkripsi (Wildan Crypto File v1)
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITER = 200_000


# -------------------------------------------------------------------
#                         KDF FUNCTION
# -------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password tidak boleh kosong.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITER,
    )

    return kdf.derive(password.encode())


# -------------------------------------------------------------------
#                         PARSE FORMAT ENCRYPTED FILE
# -------------------------------------------------------------------
def parse_encrypted(blob: bytes):
    """Format file:
       MAGIC (4) + SALT (16) + NONCE (12) + CIPHERTEXT+TAG (sisa)
    """
    if len(blob) < 4 + SALT_SIZE + NONCE_SIZE:
        raise ValueError("Format file terenkripsi tidak valid ( terlalu pendek ).")

    if blob[:4] != MAGIC:
        raise ValueError("Bukan file terenkripsi oleh aplikasi ini (MAGIC salah).")

    salt = blob[4:4 + SALT_SIZE]
    nonce = blob[4 + SALT_SIZE:4 + SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[4 + SALT_SIZE + NONCE_SIZE:]

    return salt, nonce, ciphertext


# -------------------------------------------------------------------
#                         ENKRIPSI FILE
# -------------------------------------------------------------------
def encrypt_file(input_path: str, password: str) -> str:
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    out_data = MAGIC + salt + nonce + ciphertext
    out_path = input_path + ".enc"

    with open(out_path, "wb") as f:
        f.write(out_data)

    return out_path


# -------------------------------------------------------------------
#                         DEKRIPSI FILE
# -------------------------------------------------------------------
def decrypt_file(input_path: str, password: str) -> str:
    with open(input_path, "rb") as f:
        blob = f.read()

    salt, nonce, ciphertext = parse_encrypted(blob)
    key = derive_key(password, salt)

    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Password salah atau file telah rusak!")

    out_path = input_path[:-4]  # hilangkan .enc

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path


# ===================================================================
#                            GUI TKINTER
# ===================================================================
class SecureGUI:

    def __init__(self, root):
        self.root = root
        root.title("Wildan AES-256 File Encryptor")
        root.geometry("450x320")
        root.resizable(False, False)

        # Label file
        tk.Label(root, text="Pilih File:", font=("Arial", 11)).pack(pady=5)

        # Field file
        self.file_entry = tk.Entry(root, width=50, font=("Arial", 10))
        self.file_entry.pack()

        # Tombol browse
        tk.Button(root, text="Browse File...", command=self.choose_file).pack(pady=5)

        # Label password
        tk.Label(root, text="Password:", font=("Arial", 11)).pack()

        # Input password
        self.pw_entry = tk.Entry(root, show="*", width=50)
        self.pw_entry.pack()

        # Tombol enkripsi
        tk.Button(
            root,
            text="🔐 ENKRIPSI FILE",
            width=25,
            bg="#4CAF50",
            fg="white",
            command=self.encrypt_click
        ).pack(pady=10)

        # Tombol dekripsi
        tk.Button(
            root,
            text="🔓 DEKRIPSI FILE",
            width=25,
            bg="#2196F3",
            fg="white",
            command=self.decrypt_click
        ).pack()

        # Status
        self.status = tk.Label(root, text="", fg="gray")
        self.status.pack(pady=10)

    # -------------------------------------------------------------------
    #                            GUI FUNCTION
    # -------------------------------------------------------------------

    def choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)

    def encrypt_click(self):
        file = self.file_entry.get().strip()
        pw = self.pw_entry.get().strip()

        if not file:
            messagebox.showerror("Error", "File belum dipilih!")
            return

        if not pw:
            messagebox.showerror("Error", "Password tidak boleh kosong!")
            return

        try:
            out = encrypt_file(file, pw)
            messagebox.showinfo("Sukses", f"File terenkripsi:\n{out}")
            self.status.config(text="Enkripsi berhasil ✓", fg="green")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Gagal enkripsi", fg="red")

    def decrypt_click(self):
        file = self.file_entry.get().strip()
        pw = self.pw_entry.get().strip()

        if not file:
            messagebox.showerror("Error", "File belum dipilih!")
            return

        if not pw:
            messagebox.showerror("Error", "Password tidak boleh kosong!")
            return

        if not file.endswith(".enc"):
            messagebox.showerror("Error", "File bukan .enc!")
            return

        try:
            out = decrypt_file(file, pw)
            messagebox.showinfo("Sukses", f"File berhasil didekripsi:\n{out}")
            self.status.config(text="Dekripsi berhasil ✓", fg="green")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Gagal dekripsi", fg="red")


# ===================================================================
#                            MAIN
# ===================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureGUI(root)
    root.mainloop()
