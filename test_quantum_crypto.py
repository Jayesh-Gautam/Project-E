#!/usr/bin/env python3
"""
Test script for quantum-resistant encryption
"""
import security

def test_kyber_encryption():
    print("=" * 60)
    print("Testing Quantum-Resistant Encryption (Kyber-1024)")
    print("=" * 60)
    
    # Generate key pair
    print("\n1. Generating Kyber-1024 key pair...")
    private_key, public_key = security.generate_key_pair()
    print(f"   ✓ Private key size: {len(private_key)} bytes")
    print(f"   ✓ Public key size: {len(public_key)} bytes")
    
    # Serialize keys
    print("\n2. Serializing keys to base64...")
    priv_serialized = security.serialize_private_key(private_key)
    pub_serialized = security.serialize_public_key(public_key)
    print(f"   ✓ Serialized private key: {priv_serialized[:50]}...")
    print(f"   ✓ Serialized public key: {pub_serialized[:50]}...")
    
    # Load keys back
    print("\n3. Loading keys from serialized format...")
    priv_loaded = security.load_private_key(priv_serialized)
    pub_loaded = security.load_public_key(pub_serialized)
    print(f"   ✓ Keys loaded successfully")
    
    # Test encryption/decryption
    print("\n4. Testing encryption/decryption...")
    test_message = "Hello, quantum-resistant world! 🔐"
    print(f"   Original message: {test_message}")
    
    encrypted = security.encrypt_with_public_key(pub_loaded, test_message)
    print(f"   ✓ Encrypted: {encrypted[:60]}...")
    
    decrypted = security.decrypt_with_private_key(priv_loaded, encrypted)
    print(f"   ✓ Decrypted: {decrypted}")
    
    # Verify
    if decrypted == test_message:
        print("\n✅ SUCCESS: Quantum-resistant encryption working correctly!")
    else:
        print("\n❌ FAILED: Decryption mismatch!")
        return False
    
    # Test group encryption (AES-GCM)
    print("\n5. Testing group encryption (AES-GCM)...")
    group_code = "TEST123"
    group_key = security.derive_group_key(group_code)
    print(f"   ✓ Derived group key from code: {group_code}")
    
    group_message = "This is a group message!"
    encrypted_group = security.encrypt_with_group_key(group_key, group_message)
    print(f"   ✓ Encrypted: {encrypted_group[:60]}...")
    
    decrypted_group = security.decrypt_with_group_key(group_key, encrypted_group)
    print(f"   ✓ Decrypted: {decrypted_group}")
    
    if decrypted_group == group_message:
        print("\n✅ SUCCESS: Group encryption working correctly!")
    else:
        print("\n❌ FAILED: Group decryption mismatch!")
        return False
    
    print("\n" + "=" * 60)
    print("All tests passed! Your chat is quantum-resistant! 🚀")
    print("=" * 60)
    return True

if __name__ == "__main__":
    try:
        test_kyber_encryption()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
