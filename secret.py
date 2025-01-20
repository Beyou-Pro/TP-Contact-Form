import secrets

secret_key = secrets.token_hex(32)  # Generates a 64-character hexadecimal string (32 bytes)
print(secret_key)