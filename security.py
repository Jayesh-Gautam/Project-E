import base64
import os
from passlib.context import CryptContext
import string
import secrets  # Use secrets for cryptographically strong random numbers
import pyotp
import time

# --- Quantum-Resistant Cryptography Imports ---
from kyber_py.kyber import Kyber1024
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Password Hashing (Unchanged) ---
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


# --- Group Code (Unchanged) ---
def generate_group_code(length: int = 6) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# --- TOTP (Unchanged) ---
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str, issuer_name: str = "SecureChatApp") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# --- Quantum-Resistant Asymmetric Encryption (Kyber-1024) ---

def generate_key_pair():
    """Generates a quantum-resistant Kyber-1024 key pair."""
    public_key, private_key = Kyber1024.keygen()
    return private_key, public_key


def serialize_private_key(private_key: bytes) -> str:
    """Serializes a Kyber private key to base64 string."""
    return base64.b64encode(private_key).decode('utf-8')


def serialize_public_key(public_key: bytes) -> str:
    """Serializes a Kyber public key to base64 string."""
    return base64.b64encode(public_key).decode('utf-8')


def load_private_key(key_data: str) -> bytes:
    """Loads a Kyber private key from base64 string."""
    return base64.b64decode(key_data.encode('utf-8'))


def load_public_key(key_data: str) -> bytes:
    """Loads a Kyber public key from base64 string."""
    return base64.b64decode(key_data.encode('utf-8'))


def encrypt_with_public_key(public_key: bytes, message: str) -> str:
    """
    Encrypts a message using quantum-resistant Kyber-1024 KEM + AES-GCM.
    Returns base64 encoded: encapsulated_key:iv:tag:ciphertext
    """
    try:
        # Use Kyber to encapsulate a shared secret
        # encaps returns (shared_secret, ciphertext_kem) per FIPS 203
        shared_secret, ciphertext_kem = Kyber1024.encaps(public_key)
        
        # Use the full shared secret as AES key (32 bytes)
        aes_key = shared_secret
        
        # Encrypt the message with AES-GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        
        # Combine: kem_ciphertext:iv:tag:message_ciphertext
        combined = (base64.b64encode(ciphertext_kem) + b':' + 
                   base64.b64encode(iv) + b':' + 
                   base64.b64encode(tag) + b':' + 
                   base64.b64encode(ciphertext))
        return combined.decode('utf-8')
    except Exception as e:
        print(f"Quantum-resistant encryption error: {e}")
        raise


def decrypt_with_private_key(private_key: bytes, encrypted_message: str) -> str:
    """
    Decrypts a message using quantum-resistant Kyber-1024 KEM + AES-GCM.
    """
    try:
        # Split the combined ciphertext
        parts = encrypted_message.split(':')
        if len(parts) != 4:
            return "[DECRYPTION FAILED: Invalid format]"
        
        ciphertext_kem = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])
        tag = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])
        
        # Use Kyber to decapsulate the shared secret
        shared_secret = Kyber1024.decaps(private_key, ciphertext_kem)
        
        # Use the full shared secret as AES key (32 bytes)
        aes_key = shared_secret
        
        # Decrypt with AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Quantum-resistant decryption error: {e}")
        import traceback
        traceback.print_exc()
        return "[DECRYPTION FAILED]"


# --- NEW for Phase 5: Symmetric (AES) Key Functions ---

def derive_group_key(group_code: str) -> bytes:
    """
    Derives a 32-byte (256-bit) encryption key from the group code.
    This is "password-based" encryption. The group code is the password.
    In a real-world app, a better key-exchange protocol would be used.
    """
    salt = b'secure-chat-salt'  # Fixed salt. Not ideal, but simple.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(group_code.encode('utf-8'))


def encrypt_with_group_key(key: bytes, message: str) -> str:
    """Encrypts a message with the shared group key. Returns base64 string."""
    iv = os.urandom(12)  # 96-bit IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag

    # Combine iv, tag, and ciphertext into one b64 string
    combined = base64.b64encode(iv) + b':' + base64.b64encode(tag) + b':' + base64.b64encode(ciphertext)
    return combined.decode('utf-8')


def decrypt_with_group_key(key: bytes, encrypted_str: str) -> str:
    """Decrypts a message with the shared group key."""
    try:
        iv_b64, tag_b64, cipher_b64 = encrypted_str.split(':')
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(cipher_b64)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Group decryption error: {e}")
        return "[GROUP DECRYPTION FAILED]"