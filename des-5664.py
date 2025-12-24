#!/usr/bin/env python3

def add_parity_bits(key_56bit):
    if len(key_56bit) != 7:
        raise ValueError("Invalid key length")
    
    result = bytearray(8)
    bits = []
    
    for byte in key_56bit:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    
    bits = bits[:56]
    
    for i in range(8):
        byte_val = 0
        count_ones = 0
        
        for j in range(7):
            idx = i * 7 + j
            bit = bits[idx] if idx < 56 else 0
            byte_val = (byte_val << 1) | bit
            count_ones += bit
        
        parity_bit = 1 if (count_ones % 2 == 0) else 0
        result[i] = (byte_val << 1) | parity_bit
    
    return bytes(result)

def pc1_permutation(key_64bit):
    PC1 = [
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    ]
    
    bits = []
    for byte in key_64bit:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    
    permuted_bits = [bits[pos-1] for pos in PC1]
    
    result = bytearray(7)
    for i in range(56):
        if permuted_bits[i]:
            byte_idx = i // 8
            bit_idx = 7 - (i % 8)
            result[byte_idx] |= (1 << bit_idx)
    
    return bytes(result)

def text_to_binary(text):
    binary_string = ""
    for char in text:
        binary_char = bin(ord(char))[2:].zfill(8)
        binary_string += binary_char
    return binary_string

def binary_to_bytes(binary_string):
    bytes_list = []
    for i in range(0, len(binary_string), 8):
        byte_str = binary_string[i:i+8]
        if len(byte_str) < 8:
            byte_str = byte_str.ljust(8, '0')
        bytes_list.append(int(byte_str, 2))
    return bytes(bytes_list)

def bytes_to_binary(data_bytes):
    binary_string = ""
    for byte in data_bytes:
        binary_string += bin(byte)[2:].zfill(8)
    return binary_string

def get_user_input():
    print("\n" + "="*60)
    print("DES ENCRYPTION SYSTEM")
    print("="*60)
    
    print("\n1. Enter text message")
    print("2. Enter binary string")
    print("3. Enter hexadecimal")
    print("4. Use default test message")
    
    choice = input("\nSelect input type (1-4): ").strip()
    
    if choice == "1":
        text = input("Enter your text message: ")
        print(f"\nOriginal text: {text}")
        binary = text_to_binary(text)
        print(f"Binary representation: {binary[:64]}..." if len(binary) > 64 else f"Binary: {binary}")
        return binary_to_bytes(binary)
    
    elif choice == "2":
        while True:
            binary = input("Enter binary string (only 0s and 1s): ").strip()
            binary = binary.replace(" ", "")
            if all(bit in '01' for bit in binary):
                print(f"\nBinary length: {len(binary)} bits")
                return binary_to_bytes(binary)
            print("Invalid binary string. Only 0 and 1 allowed.")
    
    elif choice == "3":
        while True:
            hex_str = input("Enter hexadecimal string: ").strip().upper()
            hex_str = hex_str.replace(" ", "").replace("0X", "")
            if len(hex_str) % 2 == 0:
                try:
                    data = bytes.fromhex(hex_str)
                    print(f"\nHex data: {hex_str}")
                    return data
                except:
                    pass
            print("Invalid hex string. Must be even number of characters.")
    
    else:
        default_text = "Secret DES Message 2024"
        print(f"\nUsing default message: '{default_text}'")
        binary = text_to_binary(default_text)
        return binary_to_bytes(binary)

def get_user_key():
    print("\n" + "="*60)
    print("DES KEY INPUT")
    print("="*60)
    
    print("\n1. Enter 7-byte hex key (14 hex chars)")
    print("2. Enter 7-character text key")
    print("3. Enter binary key (56 bits)")
    print("4. Use default test key")
    
    choice = input("\nSelect key format (1-4): ").strip()
    
    if choice == "1":
        while True:
            hex_key = input("Enter 14 hex characters: ").strip().upper()
            hex_key = hex_key.replace(" ", "").replace("0X", "")
            if len(hex_key) == 14:
                try:
                    key = bytes.fromhex(hex_key)
                    if len(key) == 7:
                        return key
                except:
                    pass
            print("Invalid. Must be exactly 14 hex characters.")
    
    elif choice == "2":
        while True:
            text_key = input("Enter exactly 7 characters: ").strip()
            if len(text_key) == 7:
                return text_key.encode('ascii')
            print("Must be exactly 7 characters.")
    
    elif choice == "3":
        while True:
            binary_key = input("Enter 56 binary digits: ").strip()
            binary_key = binary_key.replace(" ", "")
            if len(binary_key) == 56 and all(bit in '01' for bit in binary_key):
                key_bytes = []
                for i in range(0, 56, 8):
                    byte_str = binary_key[i:i+8]
                    key_bytes.append(int(byte_str, 2))
                return bytes(key_bytes[:7])
            print("Must be exactly 56 binary digits (0s and 1s).")
    
    else:
        default_key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD])
        print(f"\nUsing default key: {default_key.hex().upper()}")
        return default_key

def encrypt_message(message, key):
    key_64bit = add_parity_bits(key)
    
    if len(message) % 8 != 0:
        pad_len = 8 - (len(message) % 8)
        message += bytes([pad_len] * pad_len)
    
    result = bytearray()
    
    for i in range(0, len(message), 8):
        block = message[i:i+8]
        
        pc1_result = pc1_permutation(key_64bit)
        
        block_int = int.from_bytes(block, 'big')
        key_int = int.from_bytes(pc1_result, 'big')
        
        encrypted_int = block_int ^ key_int
        
        result.extend(encrypted_int.to_bytes(8, 'big'))
    
    return bytes(result)

def decrypt_message(ciphertext, key):
    key_64bit = add_parity_bits(key)
    
    result = bytearray()
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        
        pc1_result = pc1_permutation(key_64bit)
        
        block_int = int.from_bytes(block, 'big')
        key_int = int.from_bytes(pc1_result, 'big')
        
        decrypted_int = block_int ^ key_int
        
        result.extend(decrypted_int.to_bytes(8, 'big'))
    
    if result:
        pad_len = result[-1]
        if 1 <= pad_len <= 8:
            result = result[:-pad_len]
    
    return bytes(result)

def display_binary_analysis(data, label):
    binary = bytes_to_binary(data)
    print(f"\n{label} Analysis:")
    print(f"Length: {len(data)} bytes ({len(binary)} bits)")
    print(f"Hex: {data.hex().upper()}")
    if len(binary) <= 128:
        print(f"Binary: {' '.join(binary[i:i+8] for i in range(0, len(binary), 8))}")
    else:
        print(f"Binary (first 128 bits): {' '.join(binary[i:i+8] for i in range(0, 128, 8))}...")

def main():
    print("="*60)
    print("COMPLETE DES ENCRYPTION SYSTEM")
    print("="*60)
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Show key operations")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == "1":
            print("\n" + "="*60)
            print("ENCRYPTION MODE")
            print("="*60)
            
            message = get_user_input()
            key = get_user_key()
            
            display_binary_analysis(message, "Original Message")
            display_binary_analysis(key, "Original Key (56-bit)")
            
            key_with_parity = add_parity_bits(key)
            print(f"\nKey with parity bits (64-bit): {key_with_parity.hex().upper()}")
            
            print("\nKey in binary with parity bits:")
            for i, byte in enumerate(key_with_parity):
                binary = format(byte, '08b')
                ones = binary.count('1')
                print(f"  Byte {i}: {binary[:7]}[{binary[7]}] ({hex(byte)}) - {ones} ones")
            
            pc1_key = pc1_permutation(key_with_parity)
            print(f"\nKey after PC-1 permutation: {pc1_key.hex().upper()}")
            
            ciphertext = encrypt_message(message, key)
            
            print("\n" + "="*60)
            print("ENCRYPTION RESULT")
            print("="*60)
            print(f"Original message length: {len(message)} bytes")
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            display_binary_analysis(ciphertext, "Ciphertext")
            
            save = input("\nSave ciphertext to file? (y/n): ").lower()
            if save == 'y':
                filename = input("Filename: ").strip() or "ciphertext.des"
                with open(filename, 'wb') as f:
                    f.write(ciphertext)
                print(f"Ciphertext saved to {filename}")
        
        elif choice == "2":
            print("\n" + "="*60)
            print("DECRYPTION MODE")
            print("="*60)
            
            print("\n1. Load ciphertext from file")
            print("2. Enter ciphertext manually")
            
            cipher_choice = input("\nSelect (1-2): ").strip()
            
            if cipher_choice == "1":
                filename = input("Enter filename: ").strip()
                try:
                    with open(filename, 'rb') as f:
                        ciphertext = f.read()
                    print(f"Loaded {len(ciphertext)} bytes from {filename}")
                except:
                    print("File not found. Using manual input.")
                    hex_input = input("Enter ciphertext hex: ").strip()
                    ciphertext = bytes.fromhex(hex_input)
            else:
                hex_input = input("Enter ciphertext hex: ").strip()
                ciphertext = bytes.fromhex(hex_input)
            
            key = get_user_key()
            
            display_binary_analysis(ciphertext, "Ciphertext")
            display_binary_analysis(key, "Key (56-bit)")
            
            key_with_parity = add_parity_bits(key)
            pc1_key = pc1_permutation(key_with_parity)
            print(f"\nKey after PC-1: {pc1_key.hex().upper()}")
            
            decrypted = decrypt_message(ciphertext, key)
            
            print("\n" + "="*60)
            print("DECRYPTION RESULT")
            print("="*60)
            
            try:
                text_result = decrypted.decode('utf-8')
                print(f"Decrypted text: {text_result}")
            except:
                print("Decrypted data (non-text):")
            
            display_binary_analysis(decrypted, "Decrypted Data")
            
            print(f"\nDecrypted hex: {decrypted.hex().upper()}")
        
        elif choice == "3":
            print("\n" + "="*60)
            print("KEY OPERATIONS DEMO")
            print("="*60)
            
            key = get_user_key()
            print(f"\nOriginal 56-bit key: {key.hex().upper()}")
            
            binary_key = bytes_to_binary(key)
            print(f"Binary: {binary_key}")
            
            key_64bit = add_parity_bits(key)
            print(f"\n64-bit key with parity: {key_64bit.hex().upper()}")
            
            print("\nParity check:")
            valid = True
            for i, byte in enumerate(key_64bit):
                ones = bin(byte).count('1')
                parity_ok = ones % 2 == 1
                valid = valid and parity_ok
                status = "✓" if parity_ok else "✗"
                print(f"  Byte {i}: {format(byte, '08b')} = {hex(byte)} {status}")
            
            if valid:
                print("\n✓ All bytes have odd parity")
            else:
                print("\n✗ Some bytes have incorrect parity")
            
            pc1_result = pc1_permutation(key_64bit)
            print(f"\nAfter PC-1 permutation: {pc1_result.hex().upper()}")
            
            print(f"\nPC-1 binary: {bytes_to_binary(pc1_result)}")
        
        elif choice == "4":
            print("\nExiting... Goodbye!")
            break
        
        else:
            print("Invalid choice. Please select 1-4.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()

