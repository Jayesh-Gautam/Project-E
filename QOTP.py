"""
Quantum One-Time Pad (QOTP) - Universal File & Text Encryption System
---------------------------------------------------------------------

Supports:
✅ Text messages
✅ Any file type (.bit, .pdf, .txt, .jpg, etc.)
✅ Base64 encoded ciphertext and key
✅ Perfectly reversible decryption
"""

import base64, json, secrets, os

# ---------- Helper functions ----------
def b64e(b: bytes) -> str:
    """Base64 encode bytes → string"""
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    """Base64 decode string → bytes"""
    return base64.b64decode(s.encode("utf-8"))

# ---------- Quantum OTP Key Generation ----------
def generate_key(length: int) -> str:
    """Generate random kX, kZ and return Base64 JSON key"""
    kx = secrets.token_bytes(length)
    kz = secrets.token_bytes(length)
    key_obj = {"kX": b64e(kx), "kZ": b64e(kz)}
    key_json = json.dumps(key_obj)
    return b64e(key_json.encode("utf-8"))

# ---------- Core Encryption ----------
def encrypt_bytes(data: bytes) -> tuple[str, str]:
    """Encrypt raw bytes → (cipher_b64, key_b64)"""
    key_b64 = generate_key(len(data))
    key_json = json.loads(b64d(key_b64).decode("utf-8"))
    kx = b64d(key_json["kX"])
    kz = b64d(key_json["kZ"])

    combined = bytes(a ^ b for a, b in zip(kx, kz))
    cipher = bytes(p ^ k for p, k in zip(data, combined))
    return b64e(cipher), key_b64

def decrypt_bytes(cipher_b64: str, key_b64: str) -> bytes:
    """Decrypt Base64 ciphertext using Base64 JSON key"""
    cipher = b64d(cipher_b64)
    key_json = json.loads(b64d(key_b64).decode("utf-8"))
    kx = b64d(key_json["kX"])
    kz = b64d(key_json["kZ"])

    if len(kx) != len(cipher) or len(kz) != len(cipher):
        raise ValueError("Key length mismatch! Wrong key or corrupted ciphertext.")

    combined = bytes(a ^ b for a, b in zip(kx, kz))
    plain = bytes(c ^ k for c, k in zip(cipher, combined))
    return plain

# ---------- Text Convenience ----------
def encrypt_text(msg: str) -> tuple[str, str]:
    return encrypt_bytes(msg.encode("utf-8"))

def decrypt_text(cipher_b64: str, key_b64: str) -> str:
    return decrypt_bytes(cipher_b64, key_b64).decode("utf-8")

# ---------- File Helpers ----------
def encrypt_file(file_path: str) -> tuple[str, str]:
    """Read any file (binary mode), encrypt → return (cipher_b64, key_b64)"""
    with open(file_path, "rb") as f:
        data = f.read()
    return encrypt_bytes(data)

def decrypt_file(cipher_b64: str, key_b64: str, output_path: str):
    """Decrypt Base64 ciphertext → save any file"""
    plain = decrypt_bytes(cipher_b64, key_b64)
    with open(output_path, "wb") as f:
        f.write(plain)

# ---------- Interactive Menu ----------
def main():
    print("=== Quantum One-Time Pad (QOTP) Encryption System ===\n")
    print("Select mode:")
    print("1. Encrypt")
    print("2. Decrypt")
    mode = input("Enter choice (1 or 2): ").strip()

    print("\nSelect data type:")
    print("1. Text message")
    print("2. File (.bit, .pdf, .txt, .jpg, etc.)")
    dtype = input("Enter choice (1 or 2): ").strip()

    # ---------------------- ENCRYPTION ----------------------
    if mode == "1":
        if dtype == "1":  # Text
            msg = input("\nEnter your message: ")
            cipher_b64, key_b64 = encrypt_text(msg)
            print("\n--- ENCRYPTION COMPLETE ---")
            print("Ciphertext (Base64):\n", cipher_b64)
            print("\nKey (Base64 JSON):\n", key_b64)
            print("\n⚠️  Save the key safely — it is required for decryption.")

        elif dtype == "2":  # File
            file_path = input("\nEnter path to your file: ").strip()
            if not os.path.exists(file_path):
                print("❌ File not found!")
                return
            cipher_b64, key_b64 = encrypt_file(file_path)
            print("\n--- ENCRYPTION COMPLETE ---")
            print("Ciphertext (Base64):\n", cipher_b64)
            print("\nKey (Base64 JSON):\n", key_b64)
            print("\n⚠️  Save this key safely — required for decryption.")
        else:
            print("Invalid data type choice.")

    # ---------------------- DECRYPTION ----------------------
    elif mode == "2":
        cipher_b64 = input("\nEnter ciphertext (Base64): ").strip()
        key_b64 = input("Enter key (Base64 JSON): ").strip()

        if dtype == "1":  # Text
            try:
                plaintext = decrypt_text(cipher_b64, key_b64)
                print("\n--- DECRYPTION COMPLETE ---")
                print("Decrypted message:\n", plaintext)
            except Exception as e:
                print("❌ Error during decryption:", e)

        elif dtype == "2":  # File
            output_path = input("Enter output filename (e.g., recovered.pdf): ").strip()
            try:
                decrypt_file(cipher_b64, key_b64, output_path)
                print("\n--- DECRYPTION COMPLETE ---")
                print(f"File decrypted and saved as: {output_path}")
            except Exception as e:
                print("❌ Error during file decryption:", e)
        else:
            print("Invalid data type choice.")

    else:
        print("Invalid mode selected. Please restart and enter 1 or 2.")

# ---------- Run ----------
if __name__ == "__main__":
    main()
