from database import Database
from auth import Auth

db = Database()
auth = Auth(db)

# создаём новый секрет и получаем URI
uri = auth.setup_2fa("sofia@example.com")
print("Provisioning URI:", uri)

# генерируем QR-код
auth.generate_qr(uri, "2fa_qr.png")
print("QR-код сохранён как 2fa_qr.png")
