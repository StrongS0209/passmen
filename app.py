import os
from getpass import getpass

from database import Database
from auth import Auth
from crypto import derive_key, encrypt, decrypt

def ensure_data_dir():
    os.makedirs("data", exist_ok=True)

def main():
    ensure_data_dir()
    db = Database()
    auth = Auth(db)

    if not auth.is_initialized():
        print("Nie ustawiono hasła głównego.")
        master = getpass("Ustaw master password: ")
        if not master:
            print("Master password nie może być puste.")
            return
        auth.initialize_master(master)
        print("Hasło główne ustawione!")

    attempts = 3
    salt = None
    while attempts > 0 and salt is None:
        master = getpass("Podaj master password: ")
        salt = auth.verify_master(master)
        if salt is None:
            attempts -= 1
            print(f"Błędne hasło główne! Pozostało prób: {attempts}")
    if salt is None:
        print("Logowanie nieudane.")
        return

    key = derive_key(master, salt)
    print("Logowanie udane!")

    while True:
        print("\n1. Dodaj nowy wpis")
        print("2. Wyświetl wpisy")
        print("3. Usuń wpis")
        print("4. Zaktualizuj wpis")
        print("5. Wyjście")
        choice = input("Wybierz opcję: ").strip()

        if choice == "1":
            service = input("Serwis: ").strip()
            login = input("Login: ").strip()
            password = getpass("Hasło: ").strip()
            enc_password = encrypt(password, key)
            db.add_entry(service, login, enc_password)
            print("Dodano wpis!")
        elif choice == "2":
            entries = db.get_entries()
            if not entries:
                print("Brak wpisów.")
                continue
            for e in entries:
                try:
                    dec_pass = decrypt(e["password"], key)
                except Exception:
                    dec_pass = "<Nie można odszyfrować>"
                print(f"[{e['id']}] Serwis: {e['service']}, Login: {e['login']}, Hasło: {dec_pass}")
        elif choice == "3":
            entry_id = input("ID wpisu do usunięcia: ").strip()
            if entry_id.isdigit():
                db.delete_entry(int(entry_id))
                print("Usunięto wpis.")
            else:
                print("Nieprawidłowe ID.")
        elif choice == "4":
            entry_id = input("ID wpisu do aktualizacji: ").strip()
            if not entry_id.isdigit():
                print("Nieprawidłowe ID.")
                continue
            service = input("Nowy serwis: ").strip()
            login = input("Nowy login: ").strip()
            password = getpass("Nowe hasło: ").strip()
            enc_password = encrypt(password, key)
            db.update_entry(int(entry_id), service, login, enc_password)
            print("Zaktualizowano wpis.")
        elif choice == "5":
            print("Do zobaczenia!")
            break
        else:
            print("Nieprawidłowa opcja!")

if __name__ == "__main__":
    main()
