#!/usr/bin/env python3

# DES S-boxes
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Permutation tables
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]


KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def add_parity_bits(key_56bit):
    """
    Ajoute les bits de parité à une clé de 56 bits pour obtenir une clé de 64 bits.
    Chaque octet reçoit un bit de parité impair à la fin pour la vérification d'erreurs.
    C'est une étape standard dans le processus de préparation de la clé DES.
    """
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
    """
    Applique la permutation PC-1 à une clé de 64 bits pour obtenir une clé de 56 bits.
    Cette permutation élimine les bits de parité et réorganise les bits restants
    pour préparer la génération des sous-clés dans l'algorithme DES.
    """
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

def generate_subkeys(key_56bit):
    """
    Génère 16 sous-clés de 48 bits à partir de la clé de 56 bits après PC-1.
    Cette fonction divise la clé en deux moitiés de 28 bits, effectue des rotations
    selon le calendrier DES, puis applique la permutation PC-2 pour créer chaque sous-clé.
    Les sous-clés sont utilisées dans les 16 tours de l'algorithme Feistel.
    """
    subkeys = []
    # Split into left and right halves (28 bits each)
    left = key_56bit[:4]  # First 28 bits (4 bytes, but we'll handle as bits)
    right = key_56bit[3:7]  # Last 28 bits (overlapping bytes)

    # Convert to bit lists for easier manipulation
    left_bits = []
    right_bits = []

    for byte in left:
        for i in range(7, -1, -1):
            left_bits.append((byte >> i) & 1)
    left_bits = left_bits[:28]

    for byte in right:
        for i in range(7, -1, -1):
            right_bits.append((byte >> i) & 1)
    right_bits = right_bits[:28]

    for round_num in range(16):
        # Rotate left and right halves
        shift = KEY_SHIFTS[round_num]
        left_bits = left_bits[shift:] + left_bits[:shift]
        right_bits = right_bits[shift:] + right_bits[:shift]

        # Combine and apply PC-2
        combined_bits = left_bits + right_bits
        subkey_bits = [combined_bits[pos-1] for pos in PC2]

        # Convert to bytes
        subkey = bytearray(6)
        for i in range(48):
            if subkey_bits[i]:
                byte_idx = i // 8
                bit_idx = 7 - (i % 8)
                subkey[byte_idx] |= (1 << bit_idx)

        subkeys.append(bytes(subkey))

    return subkeys

def feistel_function(right_half, subkey):
    """
    Fonction Feistel (f) pour DES : expansion, XOR avec la sous-clé, substitution S-box, permutation P.
    Cette fonction est le cœur de l'algorithme DES, appliquant une transformation complexe
    à la moitié droite du bloc de données en utilisant la sous-clé correspondante.
    Elle produit une sortie de 32 bits qui sera XORée avec la moitié gauche.
    """
    # Expansion E: 32 bits -> 48 bits
    expanded = []
    for pos in E:
        bit_pos = pos - 1
        byte_idx = bit_pos // 8
        bit_idx = 7 - (bit_pos % 8)
        expanded.append((right_half[byte_idx] >> bit_idx) & 1)

    # XOR with subkey (48 bits)
    subkey_bits = []
    for byte in subkey:
        for i in range(7, -1, -1):
            subkey_bits.append((byte >> i) & 1)
    subkey_bits = subkey_bits[:48]

    xored = [expanded[i] ^ subkey_bits[i] for i in range(48)]

    # S-box substitution: 48 bits -> 32 bits
    output_32 = []
    for sbox_idx in range(8):
        # 6 bits per S-box
        start = sbox_idx * 6
        six_bits = xored[start:start+6]

        # Row: bits 0 and 5
        row = (six_bits[0] << 1) | six_bits[5]
        # Column: bits 1-4
        col = (six_bits[1] << 3) | (six_bits[2] << 2) | (six_bits[3] << 1) | six_bits[4]

        # Get value from S-box
        sbox_value = S_BOXES[sbox_idx][row][col]

        # Convert to 4 bits
        for i in range(3, -1, -1):
            output_32.append((sbox_value >> i) & 1)

    # Permutation P: 32 bits -> 32 bits
    permuted = [output_32[pos-1] for pos in P]

    # Convert back to bytes
    result = bytearray(4)
    for i in range(32):
        if permuted[i]:
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
    """
    Convertit une chaîne binaire en objet bytes.
    La chaîne est divisée en groupes de 8 bits, chacun étant converti en un octet.
    Si la longueur n'est pas un multiple de 8, le dernier groupe est complété par des zéros.
    Cette fonction est utilisée pour transformer les données binaires en format bytes pour DES.
    """
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
    """
    Fonction interactive pour obtenir l'entrée de l'utilisateur pour le chiffrement.
    Offre plusieurs options : texte, binaire, hexadécimal ou message par défaut.
    Convertit l'entrée en bytes pour le traitement DES.
    """
    print("\n" + "="*60)
    print("SYSTÈME DE CHIFFREMENT DES")
    print("="*60)

    print("\n1. Entrer un message texte")
    print("2. Entrer une chaîne binaire")
    print("3. Entrer une valeur hexadécimale")
    print("4. Utiliser le message de test par défaut")

    choice = input("\nSélectionnez le type d'entrée (1-4) : ").strip()

    if choice == "1":
        text = input("Entrez votre message texte : ")
        print(f"\nTexte original : {text}")
        binary = text_to_binary(text)
        print(f"Représentation binaire : {binary[:64]}..." if len(binary) > 64 else f"Binaire : {binary}")
        return binary_to_bytes(binary)

    elif choice == "2":
        while True:
            binary = input("Entrez une chaîne binaire (seulement des 0 et des 1) : ").strip()
            binary = binary.replace(" ", "")
            if all(bit in '01' for bit in binary):
                print(f"\nLongueur binaire : {len(binary)} bits")
                return binary_to_bytes(binary)
            print("Chaîne binaire invalide. Seulement des 0 et des 1 autorisés.")

    elif choice == "3":
        while True:
            hex_str = input("Entrez une chaîne hexadécimale : ").strip().upper()
            hex_str = hex_str.replace(" ", "").replace("0X", "")
            if len(hex_str) % 2 == 0:
                try:
                    data = bytes.fromhex(hex_str)
                    print(f"\nDonnées hex : {hex_str}")
                    return data
                except:
                    pass
            print("Chaîne hex invalide. Doit avoir un nombre pair de caractères.")

    else:
        default_text = "Message secret DES 2024"
        print(f"\nUtilisation du message par défaut : '{default_text}'")
        binary = text_to_binary(default_text)
        return binary_to_bytes(binary)

def get_user_key():
    print("\n" + "="*60)
    print("ENTRÉE DE CLÉ DES")
    print("="*60)

    print("\n1. Entrer une clé hex de 7 octets (14 caractères hex)")
    print("2. Entrer une clé texte de 7 caractères")
    print("3. Entrer une clé binaire (56 bits)")
    print("4. Utiliser la clé de test par défaut")

    choice = input("\nSélectionnez le format de clé (1-4) : ").strip()

    if choice == "1":
        while True:
            hex_key = input("Entrez 14 caractères hexadécimaux : ").strip().upper()
            hex_key = hex_key.replace(" ", "").replace("0X", "")
            if len(hex_key) == 14:
                try:
                    key = bytes.fromhex(hex_key)
                    if len(key) == 7:
                        return key
                except:
                    pass
            print("Invalide. Doit être exactement 14 caractères hexadécimaux.")

    elif choice == "2":
        while True:
            text_key = input("Entrez exactement 7 caractères : ").strip()
            if len(text_key) == 7:
                return text_key.encode('ascii')
            print("Doit être exactement 7 caractères.")

    elif choice == "3":
        while True:
            binary_key = input("Entrez 56 chiffres binaires : ").strip()
            binary_key = binary_key.replace(" ", "")
            if len(binary_key) == 56 and all(bit in '01' for bit in binary_key):
                key_bytes = []
                for i in range(0, 56, 8):
                    byte_str = binary_key[i:i+8]
                    key_bytes.append(int(byte_str, 2))
                return bytes(key_bytes[:7])
            print("Doit être exactement 56 chiffres binaires (0 et 1).")

    else:
        default_key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD])
        print(f"\nUtilisation de la clé par défaut : {default_key.hex().upper()}")
        return default_key

def encrypt_message(message, key):
    """
    Chiffre un message en utilisant l'algorithme DES.
    Applique le padding PKCS#7 si nécessaire, génère les sous-clés,
    et traite le message par blocs de 64 bits avec 16 tours Feistel.
    Retourne le texte chiffré en bytes.
    """
    key_64bit = add_parity_bits(key)

    if len(message) % 8 != 0:
        pad_len = 8 - (len(message) % 8)
        message += bytes([pad_len] * pad_len)

    result = bytearray()

    # Generate subkeys once for all blocks
    pc1_key = pc1_permutation(key_64bit)
    subkeys = generate_subkeys(pc1_key)

    for i in range(0, len(message), 8):
        block = message[i:i+8]

        # Initial Permutation (IP)
        ip_bits = []
        for pos in IP:
            bit_pos = pos - 1
            byte_idx = bit_pos // 8
            bit_idx = 7 - (bit_pos % 8)
            ip_bits.append((block[byte_idx] >> bit_idx) & 1)

        # Split into left and right halves (32 bits each)
        left = ip_bits[:32]
        right = ip_bits[32:]

        # 16 Feistel rounds
        for round_num in range(16):
            # Save right half
            right_old = right[:]

            # Feistel function on right half
            right_bytes = bytes([sum(bit << (7 - j) for j, bit in enumerate(right[i:i+8])) for i in range(0, 32, 8)])
            f_result = feistel_function(right_bytes, subkeys[round_num])

            # Convert f_result back to bits
            f_bits = []
            for byte in f_result:
                for j in range(7, -1, -1):
                    f_bits.append((byte >> j) & 1)

            # XOR left half with f_result
            left_new = [left[k] ^ f_bits[k] for k in range(32)]

            # Swap halves
            left = right_old
            right = left_new

        # Combine halves (note: after 16 rounds, left and right are swapped)
        combined_bits = right + left

        # Final Permutation (FP)
        fp_bits = [combined_bits[pos-1] for pos in FP]

        # Convert back to bytes
        encrypted_block = bytearray(8)
        for j in range(64):
            if fp_bits[j]:
                byte_idx = j // 8
                bit_idx = 7 - (j % 8)
                encrypted_block[byte_idx] |= (1 << bit_idx)

        result.extend(encrypted_block)

    return bytes(result)

def decrypt_message(ciphertext, key):
    key_64bit = add_parity_bits(key)

    result = bytearray()

    # Generate subkeys once for all blocks
    pc1_key = pc1_permutation(key_64bit)
    subkeys = generate_subkeys(pc1_key)

    # For decryption, use subkeys in reverse order
    subkeys = subkeys[::-1]

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]

        # Initial Permutation (IP)
        ip_bits = []
        for pos in IP:
            bit_pos = pos - 1
            byte_idx = bit_pos // 8
            bit_idx = 7 - (bit_pos % 8)
            ip_bits.append((block[byte_idx] >> bit_idx) & 1)

        # Split into left and right halves (32 bits each)
        left = ip_bits[:32]
        right = ip_bits[32:]

        # 16 Feistel rounds (same as encryption but with reversed subkeys)
        for round_num in range(16):
            # Save right half
            right_old = right[:]

            # Feistel function on right half
            right_bytes = bytes([(sum(bit << (7 - j) for j, bit in enumerate(right[i:i+8]))) for i in range(0, 32, 8)])
            f_result = feistel_function(right_bytes, subkeys[round_num])

            # Convert f_result back to bits
            f_bits = []
            for byte in f_result:
                for j in range(7, -1, -1):
                    f_bits.append((byte >> j) & 1)

            # XOR left half with f_result
            left_new = [left[k] ^ f_bits[k] for k in range(32)]

            # Swap halves
            left = right_old
            right = left_new

        # Combine halves (note: after 16 rounds, left and right are swapped)
        combined_bits = right + left

        # Final Permutation (FP)
        fp_bits = [combined_bits[pos-1] for pos in FP]

        # Convert back to bytes
        decrypted_block = bytearray(8)
        for j in range(64):
            if fp_bits[j]:
                byte_idx = j // 8
                bit_idx = 7 - (j % 8)
                decrypted_block[byte_idx] |= (1 << bit_idx)

        result.extend(decrypted_block)

    # Remove padding
    if result:
        pad_len = result[-1]
        if 1 <= pad_len <= 8:
            result = result[:-pad_len]

    return bytes(result)

def display_binary_analysis(data, label):
    binary = bytes_to_binary(data)
    print(f"\n{label} Analyse :")
    print(f"Longueur : {len(data)} octets ({len(binary)} bits)")
    print(f"Hex : {data.hex().upper()}")
    if len(binary) <= 128:
        print(f"Binaire : {' '.join(binary[i:i+8] for i in range(0, len(binary), 8))}")
    else:
        print(f"Binaire (premiers 128 bits) : {' '.join(binary[i:i+8] for i in range(0, 128, 8))}...")

def main():
    print("="*60)
    print("SYSTÈME COMPLET DE CHIFFREMENT DES")
    print("="*60)

    while True:
        print("\n" + "="*60)
        print("MENU PRINCIPAL")
        print("="*60)
        print("1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Afficher les opérations de clé")
        print("4. Quitter")

        choice = input("\nSélectionnez une option (1-4) : ").strip()
        
        if choice == "1":
            print("\n" + "="*60)
            print("MODE CHIFFREMENT")
            print("="*60)

            message = get_user_input()
            key = get_user_key()

            display_binary_analysis(message, "Message Original")
            display_binary_analysis(key, "Clé Originale (56-bit)")

            key_with_parity = add_parity_bits(key)
            print(f"\nClé avec bits de parité (64-bit) : {key_with_parity.hex().upper()}")

            print("\nClé en binaire avec bits de parité :")
            for i, byte in enumerate(key_with_parity):
                binary = format(byte, '08b')
                ones = binary.count('1')
                print(f"  Octet {i} : {binary[:7]}[{binary[7]}] ({hex(byte)}) - {ones} uns")

            pc1_key = pc1_permutation(key_with_parity)
            print(f"\nClé après permutation PC-1 : {pc1_key.hex().upper()}")

            ciphertext = encrypt_message(message, key)

            print("\n" + "="*60)
            print("RÉSULTAT DU CHIFFREMENT")
            print("="*60)
            print(f"Longueur du message original : {len(message)} octets")
            print(f"Longueur du texte chiffré : {len(ciphertext)} octets")
            display_binary_analysis(ciphertext, "Texte Chiffré")

            save = input("\nSauvegarder le texte chiffré dans un fichier ? (o/n) : ").lower()
            if save == 'o':
                filename = input("Nom du fichier : ").strip() or "ciphertext.des"
                with open(filename, 'wb') as f:
                    f.write(ciphertext)
                print(f"Texte chiffré sauvegardé dans {filename}")
        
        elif choice == "2":
            print("\n" + "="*60)
            print("MODE DÉCHIFFREMENT")
            print("="*60)

            print("\n1. Charger le texte chiffré depuis un fichier")
            print("2. Entrer le texte chiffré manuellement")

            cipher_choice = input("\nSélectionnez (1-2) : ").strip()

            if cipher_choice == "1":
                filename = input("Entrez le nom du fichier : ").strip()
                try:
                    with open(filename, 'rb') as f:
                        ciphertext = f.read()
                    print(f"Chargé {len(ciphertext)} octets depuis {filename}")
                except:
                    print("Fichier non trouvé. Utilisation de l'entrée manuelle.")
                    hex_input = input("Entrez le texte chiffré hex : ").strip()
                    ciphertext = bytes.fromhex(hex_input)
            else:
                hex_input = input("Entrez le texte chiffré hex : ").strip()
                ciphertext = bytes.fromhex(hex_input)

            key = get_user_key()

            display_binary_analysis(ciphertext, "Texte Chiffré")
            display_binary_analysis(key, "Clé (56-bit)")

            key_with_parity = add_parity_bits(key)
            pc1_key = pc1_permutation(key_with_parity)
            print(f"\nClé après PC-1 : {pc1_key.hex().upper()}")

            decrypted = decrypt_message(ciphertext, key)

            print("\n" + "="*60)
            print("RÉSULTAT DU DÉCHIFFREMENT")
            print("="*60)

            try:
                text_result = decrypted.decode('utf-8')
                print(f"Texte déchiffré : {text_result}")
            except:
                print("Données déchiffrées (non-texte) :")

            display_binary_analysis(decrypted, "Données Déchiffrées")

            print(f"\nHex déchiffré : {decrypted.hex().upper()}")
        
        elif choice == "3":
            print("\n" + "="*60)
            print("DÉMO DES OPÉRATIONS DE CLÉ")
            print("="*60)

            key = get_user_key()
            print(f"\nClé originale 56-bit : {key.hex().upper()}")

            binary_key = bytes_to_binary(key)
            print(f"Binaire : {binary_key}")

            key_64bit = add_parity_bits(key)
            print(f"\nClé 64-bit avec parité : {key_64bit.hex().upper()}")

            print("\nVérification de parité :")
            valid = True
            for i, byte in enumerate(key_64bit):
                ones = bin(byte).count('1')
                parity_ok = ones % 2 == 1
                valid = valid and parity_ok
                status = "✓" if parity_ok else "✗"
                print(f"  Octet {i} : {format(byte, '08b')} = {hex(byte)} {status}")

            if valid:
                print("\n Tous les octets ont une parité impaire")
            else:
                print("\n Certains octets ont une parité incorrecte")

            pc1_result = pc1_permutation(key_64bit)
            print(f"\nAprès permutation PC-1 : {pc1_result.hex().upper()}")

            print(f"\nBinaire PC-1 : {bytes_to_binary(pc1_result)}")

            # Generate and display subkeys
            subkeys = generate_subkeys(pc1_result)
            print(f"\nGénération des 16 sous-clés (48 bits chacune) :")
            print("="*60)

            for i, subkey in enumerate(subkeys):
                print(f"Sous-clé {i+1:2d} : {subkey.hex().upper()}")
                # Show binary representation (first 24 bits for readability)
                binary = bytes_to_binary(subkey)
                print(f"             {' '.join(binary[j:j+8] for j in range(0, 24, 8))}...")

            print(f"\nNombre total de sous-clés générées : {len(subkeys)}")

        elif choice == "4":
            print("\nSortie... Au revoir !")
            break

        else:
            print("Choix invalide. Veuillez sélectionner 1-4.")

        input("\nAppuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
    