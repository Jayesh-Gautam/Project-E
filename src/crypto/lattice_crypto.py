"""
Lattice-based cryptography implementation
Using NTRU-like encryption for post-quantum security
"""

import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import numpy as np

class LatticeCrypto:
    def __init__(self, n=251, q=128):
        """Initialize lattice parameters"""
        self.n = n  # Polynomial degree
        self.q = q  # Modulus
        
    def generate_keypair(self):
        """Generate public/private key pair"""
        # Simplified lattice key generation
        private_key = np.random.randint(0, self.q, self.n)
        
        # Generate random polynomial for public key
        a = np.random.randint(0, self.q, self.n)
        e = np.random.randint(-2, 3, self.n)  # Small error
        
        public_key = (a * private_key + e) % self.q
        
        return {
            'private': private_key.tolist(),
            'public': {'a': a.tolist(), 'b': public_key.tolist()}
        }
    
    def encrypt_message(self, message: str, public_key: dict) -> bytes:
        """Encrypt message using lattice-based encryption"""
        # Convert message to bytes
        msg_bytes = message.encode('utf-8')
        
        # Use AES for actual message encryption (hybrid approach)
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad message
        pad_len = 16 - (len(msg_bytes) % 16)
        padded_msg = msg_bytes + bytes([pad_len] * pad_len)
        
        encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()
        
        # Encrypt AES key with lattice crypto (simplified)
        encrypted_key = self._lattice_encrypt_key(aes_key, public_key)
        
        return iv + encrypted_key + encrypted_msg
    
    def decrypt_message(self, encrypted_data: bytes, private_key: list) -> str:
        """Decrypt message using lattice-based decryption"""
        iv = encrypted_data[:16]
        encrypted_key = encrypted_data[16:48]  # 32 bytes for AES key
        encrypted_msg = encrypted_data[48:]
        
        # Decrypt AES key with lattice crypto
        aes_key = self._lattice_decrypt_key(encrypted_key, private_key)
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        padded_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
        
        # Remove padding
        pad_len = padded_msg[-1]
        message = padded_msg[:-pad_len]
        
        return message.decode('utf-8')
    
    def _lattice_encrypt_key(self, key: bytes, public_key: dict) -> bytes:
        """Simplified lattice encryption for AES key"""
        # This is a simplified version - in production use proper NTRU/Kyber
        a = np.array(public_key['a'])
        b = np.array(public_key['b'])
        
        # Convert key to polynomial representation
        key_poly = np.frombuffer(key, dtype=np.uint8)[:self.n] % self.q
        
        # Add noise and encrypt
        r = np.random.randint(0, 3, self.n)
        e1 = np.random.randint(-1, 2, self.n)
        e2 = np.random.randint(-1, 2, self.n)
        
        c1 = (a * r + e1) % self.q
        c2 = (b * r + e2 + key_poly) % self.q
        
        # Return first 32 bytes as encrypted key
        result = np.concatenate([c1[:16], c2[:16]]) % 256
        return result.astype(np.uint8).tobytes()
    
    def _lattice_decrypt_key(self, encrypted_key: bytes, private_key: list) -> bytes:
        """Simplified lattice decryption for AES key"""
        # This is a simplified version
        encrypted_array = np.frombuffer(encrypted_key, dtype=np.uint8)
        c1 = encrypted_array[:16]
        c2 = encrypted_array[16:]
        
        s = np.array(private_key[:16])
        
        # Decrypt
        decrypted = (c2 - c1 * s) % self.q % 256
        
        # Pad to 32 bytes for AES key
        result = np.zeros(32, dtype=np.uint8)
        result[:len(decrypted)] = decrypted
        
        return result.tobytes()