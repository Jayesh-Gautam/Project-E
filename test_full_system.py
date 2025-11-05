#!/usr/bin/env python3
"""
Full system test for quantum-resistant chat application
Tests all encryption scenarios
"""
import security

def test_full_encryption_flow():
    print("=" * 70)
    print("FULL SYSTEM TEST - Quantum-Resistant Chat")
    print("=" * 70)
    
    # Simulate Alice and Bob
    print("\n📝 Scenario: Alice wants to send a DM to Bob")
    print("-" * 70)
    
    # 1. Alice and Bob generate their keys
    print("\n1️⃣  Key Generation")
    print("   Alice generating Kyber-1024 keys...")
    alice_private, alice_public = security.generate_key_pair()
    print(f"   ✓ Alice's public key: {len(alice_public)} bytes")
    
    print("   Bob generating Kyber-1024 keys...")
    bob_private, bob_public = security.generate_key_pair()
    print(f"   ✓ Bob's public key: {len(bob_public)} bytes")
    
    # 2. Alice sends a DM to Bob
    print("\n2️⃣  Direct Message (Alice → Bob)")
    dm_message = "Hey Bob! This message is quantum-safe! 🔐"
    print(f"   Plaintext: {dm_message}")
    
    # Alice encrypts with Bob's public key
    encrypted_dm = security.encrypt_with_public_key(bob_public, dm_message)
    print(f"   ✓ Encrypted (Kyber-1024+AES-GCM): {encrypted_dm[:60]}...")
    
    # Bob decrypts with his private key
    decrypted_dm = security.decrypt_with_private_key(bob_private, encrypted_dm)
    print(f"   ✓ Decrypted: {decrypted_dm}")
    
    if decrypted_dm == dm_message:
        print("   ✅ DM encryption/decryption successful!")
    else:
        print("   ❌ DM test FAILED!")
        return False
    
    # 3. Group chat scenario
    print("\n3️⃣  Group Chat (Alice, Bob, Charlie in group 'TEAM42')")
    group_code = "TEAM42"
    group_message = "Team meeting at 3pm!"
    print(f"   Group code: {group_code}")
    print(f"   Plaintext: {group_message}")
    
    # Derive group key
    group_key = security.derive_group_key(group_code)
    print(f"   ✓ Derived group key: {len(group_key)} bytes")
    
    # Alice encrypts for the group
    encrypted_group = security.encrypt_with_group_key(group_key, group_message)
    print(f"   ✓ Encrypted (AES-256-GCM): {encrypted_group[:60]}...")
    
    # Bob decrypts (he's in the group)
    decrypted_group = security.decrypt_with_group_key(group_key, encrypted_group)
    print(f"   ✓ Bob decrypted: {decrypted_group}")
    
    if decrypted_group == group_message:
        print("   ✅ Group encryption/decryption successful!")
    else:
        print("   ❌ Group test FAILED!")
        return False
    
    # 4. Test key serialization (for storage)
    print("\n4️⃣  Key Serialization (for storage)")
    alice_pub_serialized = security.serialize_public_key(alice_public)
    alice_priv_serialized = security.serialize_private_key(alice_private)
    print(f"   ✓ Serialized Alice's public key: {alice_pub_serialized[:50]}...")
    print(f"   ✓ Serialized Alice's private key: {alice_priv_serialized[:50]}...")
    
    # Load them back
    alice_pub_loaded = security.load_public_key(alice_pub_serialized)
    alice_priv_loaded = security.load_private_key(alice_priv_serialized)
    print("   ✓ Keys loaded successfully")
    
    # Test with loaded keys
    test_msg = "Testing with loaded keys"
    enc = security.encrypt_with_public_key(alice_pub_loaded, test_msg)
    dec = security.decrypt_with_private_key(alice_priv_loaded, enc)
    
    if dec == test_msg:
        print("   ✅ Key serialization working correctly!")
    else:
        print("   ❌ Key serialization test FAILED!")
        return False
    
    # 5. Test password hashing (bonus)
    print("\n5️⃣  Password Security (Argon2)")
    password = "SuperSecret123!"
    hashed = security.hash_password(password)
    print(f"   ✓ Password hashed: {hashed[:50]}...")
    
    if security.verify_password(password, hashed):
        print("   ✅ Password verification working!")
    else:
        print("   ❌ Password test FAILED!")
        return False
    
    # 6. Test TOTP (2FA)
    print("\n6️⃣  Two-Factor Authentication (TOTP)")
    totp_secret = security.generate_totp_secret()
    print(f"   ✓ Generated TOTP secret: {totp_secret}")
    
    import pyotp
    totp = pyotp.TOTP(totp_secret)
    code = totp.now()
    print(f"   ✓ Current code: {code}")
    
    if security.verify_totp_code(totp_secret, code):
        print("   ✅ TOTP verification working!")
    else:
        print("   ❌ TOTP test FAILED!")
        return False
    
    # Summary
    print("\n" + "=" * 70)
    print("🎉 ALL TESTS PASSED!")
    print("=" * 70)
    print("\n✅ Quantum-Resistant Encryption: READY")
    print("✅ Direct Messages: Kyber-1024 + AES-256-GCM")
    print("✅ Group Messages: AES-256-GCM")
    print("✅ Password Security: Argon2")
    print("✅ Two-Factor Auth: TOTP")
    print("\n🚀 Your chat application is quantum-safe and ready to use!")
    print("=" * 70)
    
    return True

if __name__ == "__main__":
    try:
        success = test_full_encryption_flow()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
