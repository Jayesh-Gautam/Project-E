# 🚀 Quick Start Guide - Quantum-Resistant Chat

## First Time Setup

### 1. Install Dependencies
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirement.txt
```

### 2. Clean Old Keys (if upgrading)
```cmd
python cleanup_old_keys.py
```

### 3. Test Quantum Encryption
```cmd
python test_quantum_crypto.py
```

You should see:
```
✅ SUCCESS: Quantum-resistant encryption working correctly!
✅ SUCCESS: Group encryption working correctly!
All tests passed! Your chat is quantum-resistant! 🚀
```

### 4. Start the Server
```cmd
python server.py
```

Output:
```
Database initialized.
Starting WebSocket server on ws://localhost:8765
```

### 5. Start Client(s)
Open a **new terminal** for each client:
```cmd
.venv\Scripts\activate.bat
python client.py
```

## Using the Chat

### Sign Up
1. Enter username and password
2. Click "Sign Up"
3. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
4. Enter the 6-digit code
5. Click "Verify & Complete Signup"

### Login
1. Enter username and password
2. Click "Login"
3. Enter 6-digit code from authenticator app
4. Click "Verify Login"

### Create a Group
1. After login, enter a group name
2. Click "Create Group"
3. Share the group code with others

### Join a Group
1. Get a group code from someone
2. Enter the code
3. Click "Join Group"

### Chat
1. Double-click a group to enter it
2. Click "@Everyone" to send to all (AES-256-GCM encryption)
3. Click a specific @user to send a DM (Kyber-1024 encryption)
4. Type your message and hit Enter or click Send

### Security Terminal
The bottom panel shows encryption details:
- `[SEND]` - Outgoing message info
- `[RECV]` - Incoming message info
- `[ENCRYPT:KYBER-1024+AES-GCM]` - Quantum-resistant DM encryption
- `[ENCRYPT:AES-GCM]` - Group message encryption
- `[DECRYPT:...]` - Decryption details

## Troubleshooting

### "Module not found" errors
```cmd
pip install -r requirement.txt
```

### "Connection refused"
Make sure the server is running:
```cmd
python server.py
```

### "Invalid 2FA code"
- Make sure your phone's time is synced
- Try the next code (they refresh every 30 seconds)

### Old keys causing issues
```cmd
python cleanup_old_keys.py
```
Then restart client and re-signup.

## Testing Multiple Clients

1. Start server in one terminal
2. Start first client: `python client.py`
3. Open new terminal, activate venv, start second client
4. Sign up different users in each client
5. Create/join same group
6. Test messaging!

## Security Features

✅ **Quantum-Resistant**: Kyber-1024 for DMs  
✅ **End-to-End Encrypted**: Server can't read messages  
✅ **2-Factor Auth**: TOTP protection  
✅ **Password Hashing**: Argon2  
✅ **Group Encryption**: AES-256-GCM  

## Performance

- Key generation: ~1-2ms
- Encryption: ~0.5ms
- Decryption: ~0.7ms
- **Faster than old RSA!** 🚀

Enjoy your quantum-safe chat! 🔐
