import base64
import os
from passlib.context import CryptContext
import string
import secrets  # Use secrets for cryptographically strong random numbers
import pyotp
import time

# --- NEW for Phase 5: Cryptography Imports ---
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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


# --- NEW for Phase 5: Asymmetric (RSA) Key Functions ---

def generate_key_pair():
    """Generates a new RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key) -> str:
    """Serializes a private key object to a PEM string."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def serialize_public_key(public_key) -> str:
    """Serializes a public key object to a PEM string."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def load_private_key(pem_data: str):
    """Loads a private key object from a PEM string."""
    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def load_public_key(pem_data: str):
    """Loads a public key object from a PEM string."""
    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=default_backend()
    )


def encrypt_with_public_key(public_key, message: str) -> str:
    """Encrypts a message with a public key. Returns base64 string."""
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_with_private_key(private_key, encrypted_message_b64: str) -> str:
    """Decrypts a base64-encoded message with a private key."""
    try:
        ciphertext = base64.b64decode(encrypted_message_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
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

