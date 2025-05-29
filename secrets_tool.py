
from cryptography.fernet import Fernet
import json
import sys

KEY_FILE = 'secret.key'
PLAIN_JSON = 'wpa_secrets.json'
ENCRYPTED_FILE = 'wpa_secrets.enc'

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    print(f"[+] Key saved to {KEY_FILE}")

def encrypt_json():
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
    fernet = Fernet(key)

    with open(PLAIN_JSON, 'rb') as f:
        plaintext = f.read()

    encrypted = fernet.encrypt(plaintext)

    with open(ENCRYPTED_FILE, 'wb') as f:
        f.write(encrypted)
    print(f"[+] Encrypted secrets saved to {ENCRYPTED_FILE}")

def decrypt_json():
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
    fernet = Fernet(key)

    with open(ENCRYPTED_FILE, 'rb') as f:
        encrypted = f.read()

    decrypted = fernet.decrypt(encrypted)
    data = json.loads(decrypted.decode())
    print(json.dumps(data, indent=2))

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ['genkey', 'encrypt', 'decrypt']:
        print("Usage: python secrets_tool.py [genkey|encrypt|decrypt]")
        sys.exit(1)

    command = sys.argv[1]
    if command == 'genkey':
        generate_key()
    elif command == 'encrypt':
        encrypt_json()
    elif command == 'decrypt':
        decrypt_json()
