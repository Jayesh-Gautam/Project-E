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


# ---Lattice-Based Cipher ---

import json
import hashlib
import secrets

N, Q = 16, 65521

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s.encode())

def rand_vec(n): return [secrets.randbelow(Q) for _ in range(n)]
def rand_mat(n): return [[secrets.randbelow(Q) for _ in range(n)] for __ in range(n)]

def dot(a, b): return sum(x * y for x, y in zip(a, b)) % Q
def matvec(A, v): return [dot(row, v) for row in A]
def matTvec(A, v): return [dot([A[i][j] for i in range(len(A))], v) for j in range(len(v))]

def ints_to_bytes(v): return b"".join(x.to_bytes(2, "little") for x in v)
def bytes_to_ints(b): return [int.from_bytes(b[i:i+2], "little") % Q for i in range(0, len(b), 2)]

# ---------- Toy Lattice Functions ----------
def lattice_keypair():
    """Generate a toy lattice public/secret key pair."""
    A, s = rand_mat(N), rand_vec(N)
    b = matvec(A, s)
    return {"A": A, "b": b}, {"s": s}

def lattice_encapsulate(pk):
    """Generate capsule and shared scalar."""
    r = rand_vec(N)
    u = matTvec(pk["A"], r)
    v = dot(pk["b"], r)
    return u, v

def lattice_decapsulate(sk, u):
    """Recover shared scalar."""
    return dot(u, sk["s"])

def derive_key_from_v(v):
    """Derive symmetric key bytes from lattice scalar."""
    return hashlib.sha256((v % Q).to_bytes(2, "little")).digest()

def keystream(key, n):
    """Generate keystream of n bytes using SHA256(key||ctr)."""
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + ctr.to_bytes(2, "little")).digest()
        ctr += 1
    return out[:n]

def xor_bytes(a, b): return bytes(x ^ y for x, y in zip(a, b))

# ---------- Group Encryption/Decryption Using Lattice ----------
def encrypt_with_group_key(group_code: str, message: str) -> str:
    """
    Encrypts message using toy lattice-based key encapsulation.
    Returns Base64-encoded combined data (cipher + key info).
    """
    pk, sk = lattice_keypair()
    u, v = lattice_encapsulate(pk)
    key = derive_key_from_v(v)
    ks = keystream(key, len(message.encode()))
    cipher = xor_bytes(message.encode(), ks)

    key_obj = {
        "s": b64e(ints_to_bytes(sk["s"])),
        "u": b64e(ints_to_bytes(u))
    }
    combined = {
        "cipher": b64e(cipher),
        "keyinfo": key_obj
    }
    return b64e(json.dumps(combined).encode())

def decrypt_with_group_key(group_code: str, encrypted_b64: str) -> str:
    """
    Decrypts Base64 message encrypted with lattice-based cipher.
    """
    try:
        combined = json.loads(b64d(encrypted_b64).decode())
        cipher = b64d(combined["cipher"])
        k = combined["keyinfo"]
        s = bytes_to_ints(b64d(k["s"]))
        u = bytes_to_ints(b64d(k["u"]))

        v = lattice_decapsulate({"s": s}, u)
        key = derive_key_from_v(v)
        ks = keystream(key, len(cipher))
        plain = xor_bytes(cipher, ks)
        return plain.decode()
    except Exception as e:
        print(f"Lattice decryption error: {e}")
        return "[LATTICE DECRYPTION FAILED]"
