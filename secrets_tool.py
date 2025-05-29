
import base64
import json
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

PLAIN_JSON = 'wpa_secrets.json'
ENCRYPTED_FILE = 'wpa_secrets.enc'
SALT_FILE = 'salt.bin'

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_salt():
    salt = os.urandom(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt

def load_salt():
    with open(SALT_FILE, 'rb') as f:
        return f.read()

def encrypt_json(passphrase):
    if not os.path.exists(SALT_FILE):
        salt = save_salt()
    else:
        salt = load_salt()

    key = derive_key(passphrase, salt)
    fernet = Fernet(key)

    with open(PLAIN_JSON, 'rb') as f:
        plaintext = f.read()
    encrypted = fernet.encrypt(plaintext)

    with open(ENCRYPTED_FILE, 'wb') as f:
        f.write(encrypted)
    print(f"[+] Encrypted secrets saved to {ENCRYPTED_FILE}")

def decrypt_json(passphrase):
    if not os.path.exists(SALT_FILE):
        print("[-] Missing salt file. Cannot derive key.")
        return

    salt = load_salt()
    key = derive_key(passphrase, salt)
    fernet = Fernet(key)

    with open(ENCRYPTED_FILE, 'rb') as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    data = json.loads(decrypted.decode())
    print(json.dumps(data, indent=2))

if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] not in ['encrypt', 'decrypt']:
        print("Usage: python secrets_tool.py [encrypt|decrypt] <passphrase>")
        sys.exit(1)

    command, passphrase = sys.argv[1], sys.argv[2]
    if command == 'encrypt':
        encrypt_json(passphrase)
    elif command == 'decrypt':
        decrypt_json(passphrase)
