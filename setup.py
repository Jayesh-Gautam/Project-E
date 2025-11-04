"""
Setup script for SecureChat
"""

from setuptools import setup, find_packages

setup(
    name="securechat",
    version="1.0.0",
    description="Lattice-based encrypted messaging application",
    author="SecureChat Team",
    packages=find_packages(),
    install_requires=[
        "PyQt5==5.15.9",
        "cryptography==41.0.7",
        "pynacl==1.5.0",
        "bcrypt==4.1.2",
        "qrcode==7.4.2",
        "pyotp==2.9.0",
        "websockets==11.0.3",
        "numpy==1.24.3",
        "Pillow==10.0.1"
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "securechat=main:main",
        ],
    },
)