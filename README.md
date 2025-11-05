# Project-E - Quantum-Resistant Secure Chat

A secure chat application with **quantum-resistant encryption** using post-quantum cryptography algorithms.

## 🔐 Security Features

- **Quantum-Resistant Encryption**: Uses Kyber-1024 (NIST-selected PQC algorithm)
- **End-to-End Encryption**: Direct messages encrypted with Kyber KEM + AES-GCM
- **Group Encryption**: AES-256-GCM for group messages
- **2-Factor Authentication**: TOTP-based 2FA for all accounts
- **Password Security**: Argon2 password hashing

## 🚀 Installation & Setup

1. Create and activate virtual environment:
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

2. Install dependencies:
```cmd
pip install -r requirement.txt
```

3. Test quantum-resistant encryption (optional):
```cmd
python test_quantum_crypto.py
```

4. Start the server:
```cmd
python server.py
```

5. Start client(s) in new terminal(s):
```cmd
python client.py
```

## 📱 Usage

1. **Sign Up**: Create account with username/password
2. **2FA Setup**: Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
3. **Login**: Enter credentials + 6-digit 2FA code
4. **Create/Join Groups**: Use group codes to join conversations
5. **Chat**: Send encrypted messages to @Everyone or specific @users

## 🔬 Encryption Details

### Direct Messages (DM)
- **Algorithm**: Kyber-1024 KEM + AES-256-GCM
- **Security Level**: NIST Level 5 (highest)
- **Quantum-Resistant**: Yes ✅

### Group Messages
- **Algorithm**: AES-256-GCM with PBKDF2 key derivation
- **Security Level**: 256-bit symmetric encryption
- **Quantum-Resistant**: Yes ✅ (for key sizes used)

### Key Storage
- Private keys stored locally in `client_private_key.pem`
- Public keys stored in server database
- Keys are regenerated if old RSA format detected

## 🛡️ Why Quantum-Resistant?

Traditional RSA and ECC encryption will be vulnerable to quantum computers using Shor's algorithm. This chat app uses **Kyber**, a lattice-based cryptography algorithm selected by NIST for post-quantum standardization, ensuring your messages remain secure even against future quantum attacks.
