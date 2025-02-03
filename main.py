from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
import secrets
import base64
import json
import getpass

def encrypt_message():
    # Get user input
    plaintext = input("Enter your secret message: ").encode()
    passphrase = getpass.getpass("Enter your encryption passphrase: ").encode()

    # Argon2id parameters (1GB RAM, 3 iterations)
    salt = secrets.token_bytes(16)
    argon_params = {
        'time_cost': 3,
        'memory_cost': 1048576,  # 1 GiB
        'parallelism': 4,
        'hash_len': 32
    }

    # Derive master key
    master_key = low_level.hash_secret_raw(
        secret=passphrase,
        salt=salt,
        type=low_level.Type.ID,
        **argon_params
    )

    # Generate random data key and IVs
    data_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    wrapping_iv = secrets.token_bytes(12)

    # Encrypt message
    aesgcm = AESGCM(data_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # Encrypt data key
    aesgcm_master = AESGCM(master_key)
    encrypted_data_key = aesgcm_master.encrypt(wrapping_iv, data_key, None)

    # Prepare output with base64 encoding for easy handling
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'salt': base64.b64encode(salt).decode(),
        'encrypted_data_key': base64.b64encode(encrypted_data_key).decode(),
        'wrapping_iv': base64.b64encode(wrapping_iv).decode(),
        'argon2_params': argon_params
    }

if __name__ == "__main__":
    encrypted = encrypt_message()
    print("\n--- ENCRYPTED OUTPUT (COPY THIS SAFELY) ---")
    print(json.dumps(encrypted, indent=2))
    print("\n⚠️ WARNING: Never store your passphrase with the encrypted data!")

def decrypt(stored_data, passphrase):
    passphrase = passphrase.encode()
    
    # Re-derive master key
    master_key = low_level.hash_secret_raw(
        secret=passphrase,
        salt=stored_data["salt"],
        time_cost=stored_data["argon2_params"]["time_cost"],
        memory_cost=stored_data["argon2_params"]["memory_cost"],
        parallelism=stored_data["argon2_params"]["parallelism"],
        hash_len=stored_data["argon2_params"]["hash_len"],
        type=low_level.Type.ID
    )
    
    # Unwrap data key
    aesgcm_master = AESGCM(master_key)
    data_key = aesgcm_master.decrypt(
        stored_data["wrapping_iv"],
        stored_data["encrypted_data_key"],
        None
    )
    
    # Decrypt plaintext
    aesgcm = AESGCM(data_key)
    plaintext = aesgcm.decrypt(
        stored_data["iv"],
        stored_data["ciphertext"],
        None
    )
    
    return plaintext.decode()