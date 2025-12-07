import os
import json
from datetime import datetime, timedelta
from io import BytesIO

from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

from database import Database
from auth import Auth
from crypto import derive_key, encrypt, decrypt, generate_password


def create_app():
    os.makedirs("data", exist_ok=True)

    app = Flask(__name__)
    app.secret_key = os.environ.get("APP_SECRET_KEY", os.urandom(16))
    app.wsgi_app = ProxyFix(app.wsgi_app)

    # ⏱️ Автоматическое wylogowanie po 10 minutach
    app.permanent_session_lifetime = timedelta(minutes=10)

    db = Database()
    auth = Auth(db)

    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            master = request.form.get("master", "")
            salt = auth.verify_master(master)
            if salt is None:
                flash("Błędne hasło główne!", "error")
                return render_template("login.html", initialized=auth.is_initialized())

            # 🔐 проверка 2FA
            code = request.form.get("code", "")
            if not auth.verify_2fa(code):
                flash("Niepoprawny kod 2FA!", "error")
                return render_template("login.html", initialized=auth.is_initialized())

            # если всё ок — сохраняем сессию
            session["salt"] = salt.hex()
            session["master"] = master
            session.permanent = True   # ⏱️ включаем таймер
            return redirect(url_for("list_passwords"))

        return render_template("login.html", initialized=auth.is_initialized())

    @app.route("/init", methods=["POST"])
    def init_master():
        if auth.is_initialized():
            flash("Hasło główne już ustawione.", "info")
            return redirect(url_for("login"))
        master = request.form.get("master", "")
        if not master:
            flash("Master password nie może być puste.", "error")
            return redirect(url_for("login"))
        auth.initialize_master(master)
        flash("Hasło główne ustawione!", "success")
        return redirect(url_for("login"))

    # Текущий ключ из сессии
    def current_key():
        salt_hex = session.get("salt")
        master = session.get("master")
        if not salt_hex or not master:
            return None
        return derive_key(master, bytes.fromhex(salt_hex))

    @app.route("/list")
    def list_passwords():
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        q = request.args.get("q", "").strip()
        entries = db.search_entries(q) if q else db.get_entries()
        decoded = []
        for e in entries:
            try:
                dec = decrypt(e["password"], key)
            except Exception:
                dec = "<Nie można odszyfrować>"
            decoded.append({**e, "decrypted": dec})
        stats = db.get_stats()
        return render_template("list.html", entries=decoded, query=q, stats=stats)

    @app.route("/add", methods=["GET", "POST"])
    def add_password():
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        if request.method == "POST":
            service = request.form.get("service", "").strip()
            login_ = request.form.get("login", "").strip()
            password = request.form.get("password", "").strip()
            if not service or not login_ or not password:
                flash("Wszystkie pola są wymagane.", "error")
                return redirect(url_for("add_password"))
            enc = encrypt(password, key)
            db.add_entry(service, login_, enc)
            flash("Dodano wpis!", "success")
            return redirect(url_for("list_passwords"))
        return render_template("add.html")

    @app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
    def edit_password(entry_id: int):
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        entry = db.get_entry(entry_id)
        if not entry:
            flash("Wpis nie istnieje.", "error")
            return redirect(url_for("list_passwords"))
        if request.method == "POST":
            service = request.form.get("service", "").strip()
            login_ = request.form.get("login", "").strip()
            password = request.form.get("password", "").strip()
            if not service or not login_ or not password:
                flash("Wszystkie pola są wymagane.", "error")
                return redirect(url_for("edit_password", entry_id=entry_id))
            enc = encrypt(password, key)
            db.update_entry(entry_id, service, login_, enc)
            flash("Zaktualizowano wpis!", "success")
            return redirect(url_for("list_passwords"))
        try:
            decrypted = decrypt(entry["password"], key)
        except Exception:
            decrypted = ""
        return render_template("edit.html", entry=entry, decrypted=decrypted)

    @app.route("/generate", methods=["GET"])
    def generate():
        try:
            length = int(request.args.get("length", "16"))
            use_symbols = request.args.get("symbols", "1") == "1"
        except ValueError:
            length, use_symbols = 16, True
        pwd = generate_password(length=length, use_symbols=use_symbols)
        return {"password": pwd}

    @app.route("/delete/<int:entry_id>", methods=["POST"])
    def delete_password(entry_id: int):
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        db.delete_entry(entry_id)
        flash("Usunięto wpis.", "success")
        return redirect(url_for("list_passwords"))

    @app.route("/export", methods=["GET"])
    def export_entries():
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        entries = db.get_entries()
        payload = {
            "version": 1,
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "entries": entries,
        }
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        buf = BytesIO(data)
        buf.seek(0)
        filename = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name=filename)

    @app.route("/import", methods=["POST"])
    def import_entries():
        key = current_key()
        if key is None:
            return redirect(url_for("login"))
        file = request.files.get("file")
        if not file:
            flash("Brak pliku do importu.", "error")
            return redirect(url_for("list_passwords"))
        try:
            payload = json.load(file.stream)
            count = 0
            for e in payload.get("entries", []):
                if {"service", "login", "password"}.issubset(e.keys()):
                    db.add_entry(e["service"], e["login"], e["password"])
                    count += 1
            flash(f"Import zakończony: {count} wpisów.", "success")
        except Exception as ex:
            flash(f"Błąd importu: {ex}", "error")
        return redirect(url_for("list_passwords"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- новый маршрут для настройки 2FA ----
    @app.route("/setup-2fa")
    def setup_2fa():
        has_secret = auth.get_2fa_secret() is not None
        if not has_secret:
            uri = auth.setup_2fa("sofia@example.com")
            filename = "static/2fa_qr.png"
            auth.generate_qr(uri, filename)
        return render_template("setup_2fa.html", has_secret=has_secret)

    # ---- страница настроек безопасности ----
    @app.route("/security")
    def security():
        return render_template("security.html", has_secret=(auth.get_2fa_secret() is not None))

    @app.route("/disable-2fa", methods=["POST"])
    def disable_2fa():
        auth.delete_2fa_secret()
        flash("2FA отключено.", "success")
        return redirect(url_for("security"))

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
