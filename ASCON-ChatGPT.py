def R(x, y):
    return ((x >> y) | (x << (64 - y))) & 0xFFFFFFFFFFFFFFFF

def pad(data):
    padding_len = 8 - (len(data) % 8)
    return data + bytes([0x80] + [0x00]*(padding_len-1))

def ascon_permutation(S, rounds):
    round_constants_12 = [
        0x00000000000000f0, 0x00000000000000e1, 0x00000000000000d2,
        0x00000000000000c3, 0x00000000000000b4, 0x00000000000000a5,
        0x0000000000000096, 0x0000000000000087, 0x0000000000000078, 
        0x0000000000000069, 0x000000000000005a, 0x000000000000004b
    ]
    round_constants_6 = [
        0x0000000000000096, 0x0000000000000087, 0x0000000000000078, 
        0x0000000000000069, 0x000000000000005a, 0x000000000000004b
    ]
    
    round_constants = round_constants_12 if rounds == 12 else round_constants_6

    for i in range(rounds):
        # Round constant injection
        S[2] ^= round_constants[i]
        # Substitution layer
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T0 = S[0]; T1 = S[1]; T2 = S[2]; T3 = S[3]; T4 = S[4]
        T0 = ~T0 & 0xFFFFFFFFFFFFFFFF
        T1 = ~T1 & 0xFFFFFFFFFFFFFFFF
        T2 = ~T2 & 0xFFFFFFFFFFFFFFFF
        T3 = ~T3 & 0xFFFFFFFFFFFFFFFF
        T4 = ~T4 & 0xFFFFFFFFFFFFFFFF
        T0 &= S[1]; T1 &= S[2]; T2 &= S[3]; T3 &= S[4]; T4 &= S[0]
        S[0] ^= T1; S[1] ^= T2; S[2] ^= T3; S[3] ^= T4; S[4] ^= T0
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] = ~S[2] & 0xFFFFFFFFFFFFFFFF
        
        # Linear diffusion layer
        S[0] ^= R(S[0], 19) ^ R(S[0], 28)
        S[1] ^= R(S[1], 61) ^ R(S[1], 39)
        S[2] ^= R(S[2], 1)  ^ R(S[2], 6)
        S[3] ^= R(S[3], 10) ^ R(S[3], 17)
        S[4] ^= R(S[4], 7)  ^ R(S[4], 41)
    return S

import struct

def to_bytes(n):
    # We are working with 64 bit values so always convert to 8 bytes
    return struct.pack('>Q', n)

def from_bytes(b):
    return int.from_bytes(b, 'big')

def xor_bytes(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def initialize(key, nonce):
    assert len(key) == 16
    assert len(nonce) == 16

    # Split the key and nonce into two 64-bit parts each
    K1, K2 = from_bytes(key[:8]), from_bytes(key[8:])
    N1, N2 = from_bytes(nonce[:8]), from_bytes(nonce[8:])

    # Initialize the state
    S = [0x80400c0600000000, K1, K2, N1, N2]
    
    # Run the initial permutation
    S = ascon_permutation(S, 12)
    S[3] ^= K1
    S[4] ^= K2
    return S

def process_associated_data(S, ad):
    original_len = len(ad)
    ad = pad(ad)

    for i in range(0, len(ad), 8):
        block = ad[i:i+8]
        block_as_int = from_bytes(block)
        S[0] ^= block_as_int
        S = ascon_permutation(S, 6)
    S[4] ^= 1

    return S

def process_data(S, data, operation):
    original_len = len(data)
    data = pad(data)
    output = bytearray()

    for i in range(0, len(data), 8):
        block = data[i:i+8]
        block_as_int = from_bytes(block)
        if operation == "encrypt":
            S[0] ^= block_as_int
            output_block = to_bytes(S[0])[:len(block)]
        else: # decrypt
            decrypted_block = S[0] ^ block_as_int
            output_block = to_bytes(decrypted_block)[:len(block)]
            S[0] ^= decrypted_block
        output += output_block
        if i != len(data) - 8:
            S = ascon_permutation(S, 6)
        elif operation == "decrypt":  # Handle last block in decryption differently
            S[0] ^= decrypted_block
            S[0] ^= 0x8000000000000000
    output = output[:original_len]
    return S, output


def finalize(S, key):
    # Copy the current state
    S_final = S.copy()
    # XOR the key to the state
    K1, K2 = from_bytes(key[:8]), from_bytes(key[8:])
    S_final[1] ^= K1
    S_final[2] ^= K2
    # Perform the permutation with 12 rounds
    S_final = ascon_permutation(S_final, 12)
    # XOR the last 128 bits of the state with the key
    S_final[3] ^= K1
    S_final[4] ^= K2
    # Pack the final 128 bits (16 bytes) as the tag
    return to_bytes(S_final[3]) + to_bytes(S_final[4])

def encrypt(key, nonce, plaintext, ad):
    S = initialize(key, nonce)
    if len(ad) == 0:
        S[4] ^= 1
    else:
        S = process_associated_data(S, ad)
    S, ciphertext = process_data(S, plaintext, "encrypt")
    tag = finalize(S, key)

    return ciphertext, tag

def decrypt(key, nonce, ciphertext, tag, ad):
    S = initialize(key, nonce)
    if len(ad) == 0:
        S[4] ^= 1
    else:
        S = process_associated_data(S, ad)
    S, plaintext = process_data(S, ciphertext, "decrypt")
    if tag != finalize(S, key):
        raise ValueError("Invalid authentication tag")

    return plaintext

def test():
    key = bytes.fromhex("1" * 32)
    nonce = bytes.fromhex("0" * 32)
    plaintext = bytes.fromhex("0" * 64)
    associated_data = bytes.fromhex("1" * 32)
    ciphertext, tag = encrypt(key, nonce, plaintext, associated_data)
    
    print("Initial plaintext: ", plaintext.hex())
    print("Key: ", key.hex())
    print("Nonce: ", nonce.hex())
    print("Associated data: ", associated_data.hex())
    print("Ciphertext: ", ciphertext.hex())
    print("Tag: ", tag.hex())
    try:
        decrypted = decrypt(key, nonce, ciphertext, tag, associated_data)
        assert decrypted == plaintext
        print("Test passed.")
    except ValueError:
        print("Test failed.")
test()