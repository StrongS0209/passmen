import base64
import hashlib
import os
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_ITERATIONS = 200_000  # Баланс безопасности и производительности


def hash_password(password: str, salt: bytes) -> str:
    """
    Хэш мастер-пароля для хранения в БД (солёный SHA-256).
    Используется только для проверки входа (не для шифрования данных).
    """
    h = hashlib.sha256()
    h.update(salt)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def derive_key(master_password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """
    Производит ключ из мастер-пароля и соли для симметричного шифрования (Fernet).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def encrypt(plaintext: str, key: bytes) -> str:
    f = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt(token: str, key: bytes) -> str:
    f = Fernet(key)
    plaintext = f.decrypt(token.encode("utf-8"))
    return plaintext.decode("utf-8")
import secrets, string

def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?/\\"
    if use_symbols:
        alphabet += symbols
    # Гарантируем наличие разных классов символов
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and (not use_symbols or any(c in symbols for c in pwd))):
            return 