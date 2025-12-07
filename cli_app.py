import argparse
from database import Database
from auth import Auth
from crypto import derive_key, encrypt, decrypt


def main():
    db = Database()
    auth = Auth(db)

    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest="command")

    # init master
    init_parser = subparsers.add_parser("init", help="Ustaw master password")
    init_parser.add_argument("master", help="Master password")

    # login
    login_parser = subparsers.add_parser("login", help="Zaloguj się")
    login_parser.add_argument("master", help="Master password")

    # add entry
    add_parser = subparsers.add_parser("add", help="Dodaj wpis")
    add_parser.add_argument("service", help="Nazwa serwisu")
    add_parser.add_argument("login", help="Login")
    add_parser.add_argument("password", help="Hasło")

    # list entries
    subparsers.add_parser("list", help="Wyświetl wszystkie wpisy")

    # delete entry
    del_parser = subparsers.add_parser("delete", help="Usuń wpis")
    del_parser.add_argument("id", type=int, help="ID wpisu")

    args = parser.parse_args()

    if args.command == "init":
        if auth.is_initialized():
            print("Master password już ustawione.")
            return
        auth.initialize_master(args.master)
        print("Master password ustawione!")

    elif args.command == "login":
        salt = auth.verify_master(args.master)
        if salt is None:
            print("Błędne hasło główne!")
            return
        global_key = derive_key(args.master, salt)
        print("Zalogowano pomyślnie.")

    elif args.command == "add":
        salt = db.get_master_record()[1]
        key = derive_key(args.password, salt)  # uwaga: tu używamy mastera
        enc = encrypt(args.password, key)
        db.add_entry(args.service, args.login, enc)
        print("Dodano wpis!")

    elif args.command == "list":
        salt = db.get_master_record()[1]
        master = input("Podaj master password: ")
        key = derive_key(master, salt)
        entries = db.get_entries()
        for e in entries:
            try:
                dec = decrypt(e["password"], key)
            except Exception:
                dec = "<Nie można odszyfrować>"
            print(f"[{e['id']}] {e['service']} | {e['login']} | {dec}")

    elif args.command == "delete":
        db.delete_entry(args.id)
        print("Usunięto wpis.")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
