# SecureChat - Lattice-based Encrypted Messaging

A desktop messaging application with post-quantum lattice-based cryptography and two-factor authentication.

## Features

- **Post-Quantum Security**: Uses lattice-based cryptography for future-proof encryption
- **Two-Factor Authentication**: TOTP-based 2FA with QR code setup
- **Selective Message Visibility**: Global chat with @username tagging for private messages
- **End-to-End Encryption**: All messages encrypted before storage
- **Desktop Application**: Built with PyQt5 for cross-platform compatibility

## Installation

1. Install Python 3.8+ and pip
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage

### First Time Setup
1. Launch the application
2. Go to the "Register" tab
3. Enter a username and password
4. Click "Generate 2FA Setup" to create a QR code
5. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)
6. Enter a 6-digit code from your authenticator to verify setup
7. Click "Register" to create your account

### Logging In
1. Enter your username and password
2. Enter the current 6-digit code from your authenticator app
3. Click "Login"

### Messaging
- **Global Messages**: Type normally and press Enter to send to everyone
- **Private Messages**: Use @username to send a message only that user can see
- **Example**: `@alice Hey, how are you?` - only Alice will see this message

## Security Features

- **Lattice-based encryption**: Resistant to quantum computer attacks
- **Key isolation**: Each user has unique encryption keys
- **2FA protection**: Prevents unauthorized access even with password compromise
- **Local storage**: Messages stored locally with encryption

## Technical Details

- **Frontend**: PyQt5 for desktop GUI
- **Crypto**: Custom lattice-based implementation with AES hybrid encryption
- **Database**: SQLite for local user and message storage
- **2FA**: TOTP (Time-based One-Time Password) implementation

## Project Structure

```
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── src/
│   ├── auth/              # Authentication modules
│   ├── crypto/            # Cryptography implementation
│   ├── database/          # Database management
│   ├── ui/                # User interface components
│   └── core/              # Core application logic
```

## Future Enhancements

- Network synchronization between multiple devices
- File sharing with encryption
- Group chat functionality
- Message history export
- Advanced key management

## Security Note

This is a demonstration implementation. For production use, consider:
- Professional cryptographic library integration (e.g., Kyber, NTRU)
- Secure key storage mechanisms
- Network security protocols
- Regular security audits
