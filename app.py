from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

# Funções de criptografia e hashing
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_message(key: bytes, plaintext: str) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(cipher.nonce + ciphertext).decode()

def decrypt_message(key: bytes, ciphertext: str) -> str:
    data = base64.b64decode(ciphertext)
    nonce, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def hash_password(password: bytes) -> str:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return base64.b64encode(salt + key).decode()

def verify_password(stored_password: str, provided_password: bytes) -> bool:
    stored_password_bytes = base64.b64decode(stored_password)
    salt = stored_password_bytes[:16]
    key = stored_password_bytes[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(provided_password, key)
        return True
    except Exception:
        return False

class PasswordManager:
    def __init__(self, master_password: str, storage_file: str):
        self.master_password = master_password.encode()
        self.storage_file = storage_file
        self.load_data()

    def load_data(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as file:
                self.data = json.load(file)
        else:
            self.data = {}

    def save_data(self):
        with open(self.storage_file, 'w') as file:
            json.dump(self.data, file, indent=4)

    def set_master_password(self, new_password: str):
        self.master_password = new_password.encode()

    def add_password(self, service: str, password: str):
        salt = os.urandom(16)
        key = generate_key(self.master_password, salt)
        encrypted_password = encrypt_message(key, password)
        self.data[service] = {'salt': base64.b64encode(salt).decode(), 'password': encrypted_password}
        self.save_data()
        print(f'Senha para {service} adicionada.')

    def get_password(self, service: str) -> str:
        if service in self.data:
            salt = base64.b64decode(self.data[service]['salt'])
            key = generate_key(self.master_password, salt)
            encrypted_password = self.data[service]['password']
            return decrypt_message(key, encrypted_password)
        else:
            print(f'Senha para {service} não encontrada.')
            return None

    def remove_password(self, service: str):
        if service in self.data:
            del self.data[service]
            self.save_data()
            print(f'Senha para {service} removida.')
        else:
            print(f'Senha para {service} não encontrada.')

# Exemplo de uso
if __name__ == "__main__":
    # Defina uma senha mestre
    master_password = 'my_master_password'
    pm = PasswordManager(master_password, 'passwords.json')

    # Adicione senhas
    pm.add_password('example.com', 'my_password_123')
    pm.add_password('another_service', 'password_456')

    # Recupere senhas
    print(f'Senha para example.com: {pm.get_password("example.com")}')
    
    # Remova uma senha
    pm.remove_password('example.com')

    # Verifique se a senha foi removida
    print(f'Senha para example.com após remoção: {pm.get_password("example.com")}')
