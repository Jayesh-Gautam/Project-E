#!/usr/bin/env python3
"""
Cleanup script to remove old RSA keys and optionally reset the database
for the quantum-resistant encryption upgrade.
"""
import os
import sys

def cleanup():
    print("=" * 60)
    print("Quantum-Resistant Encryption Upgrade - Cleanup Script")
    print("=" * 60)
    
    files_to_check = [
        ("client_private_key.pem", "Old client key file"),
        ("chat.db", "Database (contains old RSA public keys)")
    ]
    
    removed = []
    
    for filename, description in files_to_check:
        if os.path.exists(filename):
            print(f"\n📁 Found: {filename}")
            print(f"   Description: {description}")
            
            response = input(f"   Delete this file? (y/N): ").strip().lower()
            
            if response == 'y':
                try:
                    os.remove(filename)
                    print(f"   ✅ Deleted: {filename}")
                    removed.append(filename)
                except Exception as e:
                    print(f"   ❌ Error deleting {filename}: {e}")
            else:
                print(f"   ⏭️  Skipped: {filename}")
        else:
            print(f"\n✓ {filename} not found (already clean)")
    
    print("\n" + "=" * 60)
    if removed:
        print(f"✅ Cleanup complete! Removed {len(removed)} file(s):")
        for f in removed:
            print(f"   - {f}")
        print("\nNext steps:")
        print("1. Run: python test_quantum_crypto.py")
        print("2. Start server: python server.py")
        print("3. Start client: python client.py")
        print("4. Sign up with new quantum-resistant keys!")
    else:
        print("No files were removed.")
    print("=" * 60)

if __name__ == "__main__":
    try:
        cleanup()
    except KeyboardInterrupt:
        print("\n\n❌ Cleanup cancelled by user.")
        sys.exit(1)
