"""
Two-Factor Authentication using TOTP
"""

import pyotp
import qrcode
import io
import base64
from PIL import Image

class TwoFactorAuth:
    def __init__(self):
        self.secret = None
    
    def generate_secret(self, username: str) -> str:
        """Generate a new TOTP secret for user"""
        self.secret = pyotp.random_base32()
        return self.secret
    
    def get_qr_code(self, username: str, app_name: str = "SecureChat") -> str:
        """Generate QR code for authenticator app setup"""
        if not self.secret:
            raise ValueError("No secret generated")
        
        totp_uri = pyotp.totp.TOTP(self.secret).provisioning_uri(
            name=username,
            issuer_name=app_name
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for display
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def verify_token(self, token: str, secret: str = None) -> bool:
        """Verify TOTP token"""
        secret_to_use = secret or self.secret
        if not secret_to_use:
            return False
        
        totp = pyotp.TOTP(secret_to_use)
        return totp.verify(token, valid_window=1)
    
    def get_current_token(self, secret: str = None) -> str:
        """Get current TOTP token (for testing)"""
        secret_to_use = secret or self.secret
        if not secret_to_use:
            return ""
        
        totp = pyotp.TOTP(secret_to_use)
        return totp.now()