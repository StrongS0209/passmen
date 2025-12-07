from typing import Optional
from crypto import hash_password, generate_salt
import pyotp
import qrcode

class Auth:
    def __init__(self, db):
        self.db = db

    # Проверка, установлен ли мастер-пароль
    def is_initialized(self) -> bool:
        return self.db.master_password_exists()

    # Инициализация мастер-пароля
    def initialize_master(self, master_password: str) -> None:
        salt = generate_salt()
        pwd_hash = hash_password(master_password, salt)
        self.db.set_master_password(pwd_hash, salt)

    # Проверка мастер-пароля
    def verify_master(self, master_password: str) -> Optional[bytes]:
        record = self.db.get_master_record()
        if record is None:
            return None
        stored_hash, salt = record
        if hash_password(master_password, salt) == stored_hash:
            return salt
        return None

    # Получение текущего 2FA-секрета
    def get_2fa_secret(self) -> Optional[str]:
        return self.db.get_2fa_secret()

    # Удаление 2FA-секрета
    def delete_2fa_secret(self) -> None:
        # используем правильный метод базы
        self.db.save_2fa_secret(None)

    # Проверка кода 2FA
    def verify_2fa(self, code: str) -> bool:
        secret = self.get_2fa_secret()
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code)

    # Генерация нового 2FA-секрета и возврат URI
    def setup_2fa(self, user_email: str = "user@example.com") -> str:
        secret = pyotp.random_base32()
        self.db.save_2fa_secret(secret)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="DiplomaProject"
        )
        return uri

    # Генерация QR-кода для сканирования в приложении-аутентификаторе
    def generate_qr(self, uri: str, filename: str = "2fa_qr.png") -> None:
        img = qrcode.make(uri)
        img.save(filename)
