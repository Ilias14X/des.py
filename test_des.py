#!/usr/bin/env python3

# Import the necessary functions from des-5664.py for testing
import importlib.util
import sys
import os

# Load the DES module
spec = importlib.util.spec_from_file_location("des_module", "des-5664.py")
des_module = importlib.util.module_from_spec(spec)
sys.modules["des_module"] = des_module
spec.loader.exec_module(des_module)

def test_des():
    # Test with default key
    key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD])

    # Test message
    message = b"Hello DES"

    print("Testing DES Encryption/Decryption")
    print(f"Original message: {message}")
    print(f"Key: {key.hex().upper()}")

    try:
        # Encrypt
        ciphertext = des_module.encrypt_message(message, key)
        print(f"Ciphertext: {ciphertext.hex().upper()}")

        # Decrypt
        decrypted = des_module.decrypt_message(ciphertext, key)
        print(f"Decrypted: {decrypted}")

        # Check if decryption matches original
        if decrypted == message:
            print("✓ SUCCESS: Encryption and decryption work correctly!")
            return True
        else:
            print("✗ FAILURE: Decryption does not match original message")
            return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

if __name__ == "__main__":
    test_des()
