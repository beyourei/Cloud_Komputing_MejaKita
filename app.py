import json
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- konfigurasi
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mejakita.db")
OPEN_HOUR = 10    # jam buka  (ubah sesuai kebutuhan)
CLOSE_HOUR = 24   # jam tutup (ubah sesuai kebutuhan)
MAX_NAME_LEN = 100  # batas panjang nama pelanggan / nama meja (ubah sesuai kebutuhan)
PHONE_RE = re.compile(r"^\+?[0-9]{9,15}$")  # angka saja, 9-15 digit, boleh diawali +
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")  # username customer: huruf, angka, underscore
MIN_PASSWORD_LEN = 8  # panjang minimal password customer (ubah sesuai kebutuhan)
LOGIN_MAX_FAILS = 5        # gagal login berturut-turut sebelum dikunci (ubah sesuai kebijakan)
LOGIN_LOCK_MINUTES = 15    # lama kunci / jendela hitung gagal login, menit (ubah sesuai kebijakan)
PAYMENT_WINDOW_MINUTES = 30  # batas waktu bayar sebelum booking batal otomatis (ubah sesuai kebijakan)
PAY_METHODS = {  # SIMULASI: label saja, belum terhubung ke payment gateway
    "va": "Transfer Bank (Virtual Account)",
    "qris": "QRIS",
    "ewallet": "E-Wallet",
}
PAY_LABELS = {
    "paid": "Lunas",
    "unpaid": "Belum dibayar",
    "expired": "Kedaluwarsa",
    "refunded": "Dikembalikan",
    "cancelled": "Dibatalkan",
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# ------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin'
);
CREATE TABLE IF NOT EXISTS venues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT
);
CREATE TABLE IF NOT EXISTS tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    venue_id INTEGER NOT NULL REFERENCES venues(id),
    name TEXT NOT NULL,
    price_per_hour INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    table_id INTEGER NOT NULL REFERENCES tables(id),
    customer_name TEXT NOT NULL,
    customer_phone TEXT,
    booking_date TEXT NOT NULL,
    start_hour INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    total INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'confirmed',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bookings_lookup
    ON bookings(table_id, booking_date, status);
"""


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    user_cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    if "full_name" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
    if "phone" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    db.execute(
        """CREATE TABLE IF NOT EXISTS login_attempts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               ip TEXT NOT NULL,
               ts REAL NOT NULL
           )"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, ip, ts)"
    )
    booking_cols = [r[1] for r in db.execute("PRAGMA table_info(bookings)")]
    if "payment_status" not in booking_cols:
        # booking lama / booking kasir dianggap lunas (bayar tunai di tempat)
        db.execute("ALTER TABLE bookings ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'paid'")
    if "payment_method" not in booking_cols:
        db.execute("ALTER TABLE bookings ADD COLUMN payment_method TEXT")
    if "paid_at" not in booking_cols:
        db.execute("ALTER TABLE bookings ADD COLUMN paid_at TEXT")
    if "pay_deadline" not in booking_cols:
        db.execute("ALTER TABLE bookings ADD COLUMN pay_deadline TEXT")
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # DATA DEMO / SIMULASI - ganti password admin sebelum dipakai serius
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )
        db.execute(
            "INSERT INTO venues (name, address) VALUES (?, ?)",
            ("MejaKita Demo Billiard", "Tangerang, Banten, Indonesia"),
        )
        for name, price in [("Meja 1", 40000), ("Meja 2", 40000), ("Meja VIP", 60000)]:
            db.execute(
                "INSERT INTO tables (venue_id, name, price_per_hour) VALUES (1, ?, ?)",
                (name, price),
            )
    # rapihin nama tempat yang dulu berlabel demo/simulasi (database lama)
    db.execute(
        "UPDATE venues SET name = 'MejaKita Billiard', address = 'Tangerang, Banten, Indonesia' "
        "WHERE name = 'MejaKita Billiard' AND address = 'Tangerang, Banten, Indonesia'"
    )
    # akun kasir demo (dibuat juga di database lama kalau belum ada)
    if db.execute("SELECT 1 FROM users WHERE username = 'kasir'").fetchone() is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("kasir", generate_password_hash("kasir123"), "kasir"),
        )
    db.commit()
    db.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ------------------------------------------------------------ keamanan dasar
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "open_hour": OPEN_HOUR, "close_hour": CLOSE_HOUR}


@app.before_request
def verify_csrf():
    if request.method == "POST":
        token = session.get("csrf")
        sent = request.form.get("csrf", "")
        if not token or not secrets.compare_digest(token, sent):
            abort(400, "CSRF token tidak valid.")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Halaman ini hanya bisa diakses oleh admin.")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapper


def staff_required(view):
    """Hanya admin & kasir. Customer diarahkan ke halaman customer."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        role = session.get("role")
        if role == "customer":
            return redirect(url_for("customer_home"))
        if role not in ("admin", "kasir"):
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def customer_required(view):
    """Hanya customer. Admin & kasir diarahkan ke dashboard."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "customer":
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapper


@app.template_filter("rp")
def rupiah(value):
    return "Rp" + "{:,}".format(int(value or 0)).replace(",", ".")


@app.template_filter("jam")
def jam(hour):
    return "{:02d}:00".format(int(hour))


# --------------------------------------------------------------------- logika
def has_conflict(db, table_id, booking_date, start, duration):
    """True kalau ada booking aktif yang jamnya bertabrakan di meja & tanggal sama."""
    end = start + duration
    row = db.execute(
        """SELECT 1 FROM bookings
           WHERE table_id = ? AND booking_date = ? AND status = 'confirmed'
             AND start_hour < ? AND (start_hour + duration) > ?
           LIMIT 1""",
        (table_id, booking_date, end, start),
    ).fetchone()
    return row is not None


# ------------------------------------------------ pembatasan percobaan login
def _login_key(username):
    return username.strip().lower(), (request.remote_addr or "unknown")


def login_lock_minutes(username):
    """Sisa menit terkunci untuk kombinasi username + IP (0 kalau tidak terkunci)."""
    name, ip = _login_key(username)
    now = time.time()
    window = LOGIN_LOCK_MINUTES * 60
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (now - window,))
    rows = db.execute(
        """SELECT ts FROM login_attempts
           WHERE username = ? AND ip = ? AND ts >= ?
           ORDER BY ts DESC LIMIT ?""",
        (name, ip, now - window, LOGIN_MAX_FAILS),
    ).fetchall()
    db.commit()
    if len(rows) < LOGIN_MAX_FAILS:
        return 0
    unlock_at = rows[-1]["ts"] + window
    return max(1, int((unlock_at - now + 59) // 60))


def record_login_failure(username):
    name, ip = _login_key(username)
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (username, ip, ts) VALUES (?, ?, ?)",
        (name, ip, time.time()),
    )
    db.commit()


def clear_login_failures(username):
    name, ip = _login_key(username)
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE username = ? AND ip = ?", (name, ip))
    db.commit()


# ------------------------------------------------ pembayaran: batas waktu bayar
@app.before_request
def expire_unpaid_bookings():
    """Booking customer yang lewat batas waktu bayar dibatalkan otomatis, jam meja kembali kosong."""
    if request.endpoint in (None, "static"):
        return
    db = get_db()
    db.execute(
        """UPDATE bookings SET status = 'cancelled', payment_status = 'expired'
           WHERE status = 'confirmed' AND payment_status = 'unpaid'
             AND pay_deadline IS NOT NULL AND pay_deadline < ?""",
        (datetime.now().isoformat(timespec="seconds"),),
    )
    db.commit()


@app.template_filter("paylabel")
def paylabel(value):
    return PAY_LABELS.get(value, value)


# ---------------------------------------------------------------------- rute
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        locked = login_lock_minutes(username)
        if locked:
            flash("Terlalu banyak percobaan login yang gagal. Coba lagi dalam {} menit.".format(locked))
            return render_template("login.html")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            clear_login_failures(username)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            if user["role"] == "customer":
                return redirect(url_for("customer_home"))
            return redirect(url_for("dashboard"))
        record_login_failure(username)
        flash("Username atau password salah.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@staff_required
def dashboard():
    db = get_db()
    today = date.today().isoformat()
    stats = {
        "tables": db.execute("SELECT COUNT(*) FROM tables WHERE active = 1").fetchone()[0],
        "today_count": db.execute(
            "SELECT COUNT(*) FROM bookings WHERE booking_date = ? AND status = 'confirmed'",
            (today,),
        ).fetchone()[0],
        "today_revenue": db.execute(
            "SELECT COALESCE(SUM(total), 0) FROM bookings WHERE booking_date = ? AND status = 'confirmed' AND payment_status = 'paid'",
            (today,),
        ).fetchone()[0],
        "all_count": db.execute(
            "SELECT COUNT(*) FROM bookings WHERE status = 'confirmed'"
        ).fetchone()[0],
    }
    upcoming = db.execute(
        """SELECT b.*, t.name AS table_name FROM bookings b
           JOIN tables t ON t.id = b.table_id
           WHERE b.status = 'confirmed' AND b.booking_date >= ?
           ORDER BY b.booking_date, b.start_hour LIMIT 8""",
        (today,),
    ).fetchall()
    return render_template("dashboard.html", stats=stats, upcoming=upcoming)


@app.route("/tables", methods=["GET", "POST"])
@admin_required
def tables():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "add":
                name = request.form.get("name", "").strip()
                price = int(request.form.get("price_per_hour", ""))
                if not name or price <= 0:
                    raise ValueError
                if len(name) > MAX_NAME_LEN:
                    flash("Nama meja maksimal {} karakter.".format(MAX_NAME_LEN))
                    return redirect(url_for("tables"))
                if db.execute(
                    "SELECT 1 FROM tables WHERE lower(name) = lower(?)", (name,)
                ).fetchone():
                    flash("Nama meja sudah dipakai. Gunakan nama lain.")
                    return redirect(url_for("tables"))
                db.execute(
                    "INSERT INTO tables (venue_id, name, price_per_hour) VALUES (1, ?, ?)",
                    (name, price),
                )
                flash("Meja ditambahkan.")
            elif action == "price":
                table_id = int(request.form.get("table_id", ""))
                price = int(request.form.get("price_per_hour", ""))
                if price <= 0:
                    raise ValueError
                db.execute(
                    "UPDATE tables SET price_per_hour = ? WHERE id = ?", (price, table_id)
                )
                flash("Tarif diperbarui.")
            elif action == "toggle":
                table_id = int(request.form.get("table_id", ""))
                db.execute(
                    "UPDATE tables SET active = 1 - active WHERE id = ?", (table_id,)
                )
                flash("Status meja diperbarui.")
            db.commit()
        except ValueError:
            flash("Input tidak valid. Nama harus diisi dan tarif harus angka lebih dari 0.")
        return redirect(url_for("tables"))
    rows = db.execute("SELECT * FROM tables ORDER BY id").fetchall()
    return render_template("tables.html", rows=rows)


@app.route("/availability")
@staff_required
def availability():
    db = get_db()
    raw = request.args.get("date", date.today().isoformat())
    try:
        chosen = date.fromisoformat(raw).isoformat()
    except ValueError:
        chosen = date.today().isoformat()
    tables_ = db.execute("SELECT * FROM tables WHERE active = 1 ORDER BY id").fetchall()
    bookings = db.execute(
        """SELECT table_id, start_hour, duration FROM bookings
           WHERE booking_date = ? AND status = 'confirmed'""",
        (chosen,),
    ).fetchall()
    busy = {t["id"]: set() for t in tables_}
    for b in bookings:
        for h in range(b["start_hour"], b["start_hour"] + b["duration"]):
            busy.setdefault(b["table_id"], set()).add(h)
    hours = list(range(OPEN_HOUR, CLOSE_HOUR))
    return render_template(
        "availability.html", chosen=chosen, tables=tables_, busy=busy, hours=hours
    )


@app.route("/book", methods=["GET", "POST"])
@staff_required
def book():
    db = get_db()
    tables_ = db.execute("SELECT * FROM tables WHERE active = 1 ORDER BY id").fetchall()
    if request.method == "POST":
        errors = []
        try:
            table_id = int(request.form.get("table_id", ""))
            start = int(request.form.get("start_hour", ""))
            duration = int(request.form.get("duration", ""))
            bdate = date.fromisoformat(request.form.get("booking_date", ""))
        except ValueError:
            flash("Input tidak valid. Periksa tanggal, jam, dan durasi.")
            return redirect(url_for("book"))

        name = request.form.get("customer_name", "").strip()
        phone = re.sub(r"[\s\-]", "", request.form.get("customer_phone", ""))
        table = db.execute(
            "SELECT * FROM tables WHERE id = ? AND active = 1", (table_id,)
        ).fetchone()

        if not name:
            errors.append("Nama pelanggan wajib diisi.")
        elif len(name) > MAX_NAME_LEN:
            errors.append("Nama pelanggan maksimal {} karakter.".format(MAX_NAME_LEN))
        if not phone:
            errors.append("No. WhatsApp wajib diisi.")
        elif not PHONE_RE.match(phone):
            errors.append("No. WhatsApp tidak valid. Gunakan angka saja (9 sampai 15 digit), boleh diawali +.")
        if table is None:
            errors.append("Meja tidak ditemukan.")
        if bdate < date.today():
            errors.append("Tanggal booking tidak boleh sudah lewat.")
        if duration < 1 or start < OPEN_HOUR or start + duration > CLOSE_HOUR:
            errors.append(
                "Jam harus di dalam jam operasional ({:02d}:00 sampai {:02d}:00) dan durasi minimal 1 jam.".format(
                    OPEN_HOUR, CLOSE_HOUR % 24
                )
            )
        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for("book"))

        db.execute("BEGIN IMMEDIATE")  # kunci tulis supaya tidak ada booking ganda
        try:
            if has_conflict(db, table_id, bdate.isoformat(), start, duration):
                db.rollback()
                flash("Meja sudah dibooking pada jam tersebut. Pilih jam atau meja lain.")
                return redirect(url_for("book"))
            code = "MK" + secrets.token_hex(3).upper()
            total = table["price_per_hour"] * duration
            db.execute(
                """INSERT INTO bookings
                   (code, table_id, customer_name, customer_phone, booking_date,
                    start_hour, duration, total, status, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?, ?)""",
                (code, table_id, name, phone, bdate.isoformat(), start, duration,
                 total, session["user_id"], datetime.now().isoformat(timespec="seconds")),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        flash("Booking berhasil. Kode booking: {} (total {}).".format(code, rupiah(total)))
        return redirect(url_for("bookings"))
    return render_template("book.html", tables=tables_, today=date.today().isoformat())


@app.route("/bookings")
@staff_required
def bookings():
    rows = get_db().execute(
        """SELECT b.*, t.name AS table_name FROM bookings b
           JOIN tables t ON t.id = b.table_id
           ORDER BY b.booking_date DESC, b.start_hour DESC"""
    ).fetchall()
    return render_template("bookings.html", rows=rows)


@app.route("/bookings/<int:booking_id>/cancel", methods=["POST"])
@staff_required
def cancel_booking(booking_id):
    db = get_db()
    db.execute(
        """UPDATE bookings SET status = 'cancelled',
               payment_status = CASE payment_status WHEN 'paid' THEN 'refunded'
                                WHEN 'unpaid' THEN 'cancelled' ELSE payment_status END
           WHERE id = ? AND status = 'confirmed'""",
        (booking_id,),
    )
    db.commit()
    flash("Booking dibatalkan. Jam meja tersebut kembali tersedia.")
    return redirect(url_for("bookings"))


@app.route("/report")
@admin_required
def report():
    db = get_db()
    today = date.today()
    try:
        d_from = date.fromisoformat(request.args.get("from", today.replace(day=1).isoformat()))
        d_to = date.fromisoformat(request.args.get("to", today.isoformat()))
    except ValueError:
        d_from, d_to = today.replace(day=1), today
    rows = db.execute(
        """SELECT b.*, t.name AS table_name FROM bookings b
           JOIN tables t ON t.id = b.table_id
           WHERE b.status = 'confirmed' AND b.payment_status = 'paid' AND b.booking_date BETWEEN ? AND ?
           ORDER BY b.booking_date, b.start_hour""",
        (d_from.isoformat(), d_to.isoformat()),
    ).fetchall()
    per_table = db.execute(
        """SELECT t.name, COUNT(*) AS n, SUM(b.total) AS revenue,
                  SUM(b.duration) AS hours
           FROM bookings b JOIN tables t ON t.id = b.table_id
           WHERE b.status = 'confirmed' AND b.payment_status = 'paid' AND b.booking_date BETWEEN ? AND ?
           GROUP BY t.id ORDER BY revenue DESC""",
        (d_from.isoformat(), d_to.isoformat()),
    ).fetchall()
    total = sum(r["total"] for r in rows)
    cancelled = db.execute(
        "SELECT COUNT(*) FROM bookings WHERE status = 'cancelled' AND booking_date BETWEEN ? AND ?",
        (d_from.isoformat(), d_to.isoformat()),
    ).fetchone()[0]
    return render_template(
        "report.html", rows=rows, per_table=per_table, total=total,
        cancelled=cancelled, d_from=d_from.isoformat(), d_to=d_to.isoformat(),
    )


# ------------------------------------------------------------ sisi customer
@app.route("/register", methods=["GET", "POST"])
def register():
    form = {}
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        phone = re.sub(r"[\s\-]", "", request.form.get("phone", ""))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form = {"full_name": full_name, "username": username, "phone": phone}
        errors = []
        if not full_name:
            errors.append("Nama lengkap wajib diisi.")
        elif len(full_name) > MAX_NAME_LEN:
            errors.append("Nama lengkap maksimal {} karakter.".format(MAX_NAME_LEN))
        if not USERNAME_RE.match(username):
            errors.append("Username 3 sampai 30 karakter, hanya huruf, angka, dan underscore.")
        if not PHONE_RE.match(phone):
            errors.append("No. WhatsApp tidak valid. Gunakan angka saja (9 sampai 15 digit), boleh diawali +.")
        if len(password) < MIN_PASSWORD_LEN:
            errors.append("Password minimal {} karakter.".format(MIN_PASSWORD_LEN))
        elif password != confirm:
            errors.append("Konfirmasi password tidak sama.")
        db = get_db()
        if not errors and db.execute(
            "SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)
        ).fetchone():
            errors.append("Username sudah dipakai. Pilih username lain.")
        if not errors:
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role, full_name, phone) "
                    "VALUES (?, ?, 'customer', ?, ?)",
                    (username, generate_password_hash(password), full_name, phone),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("Username sudah dipakai. Pilih username lain.")
        if not errors:
            flash("Akun berhasil dibuat. Silakan masuk.")
            return redirect(url_for("login"))
        for e in errors:
            flash(e)
    return render_template("register.html", form=form, min_password=MIN_PASSWORD_LEN)


@app.route("/c")
@customer_required
def customer_home():
    db = get_db()
    today = date.today()
    try:
        chosen = date.fromisoformat(request.args.get("date", today.isoformat()))
    except ValueError:
        chosen = today
    if chosen < today:
        chosen = today
    venue = db.execute("SELECT * FROM venues ORDER BY id LIMIT 1").fetchone()
    tables_ = db.execute("SELECT * FROM tables WHERE active = 1 ORDER BY id").fetchall()
    rows = db.execute(
        """SELECT table_id, start_hour, duration FROM bookings
           WHERE booking_date = ? AND status = 'confirmed'""",
        (chosen.isoformat(),),
    ).fetchall()
    busy = {t["id"]: set() for t in tables_}
    for b in rows:
        for h in range(b["start_hour"], b["start_hour"] + b["duration"]):
            busy.setdefault(b["table_id"], set()).add(h)
    return render_template(
        "c_home.html", venue=venue, tables=tables_, busy=busy,
        hours=list(range(OPEN_HOUR, CLOSE_HOUR)), chosen=chosen.isoformat(),
        today=today.isoformat(), is_today=(chosen == today), now_hour=datetime.now().hour,
    )


@app.route("/c/book", methods=["GET", "POST"])
@customer_required
def customer_book():
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    tables_ = db.execute("SELECT * FROM tables WHERE active = 1 ORDER BY id").fetchall()
    today = date.today()
    if request.method == "POST":
        try:
            table_id = int(request.form.get("table_id", ""))
            start = int(request.form.get("start_hour", ""))
            duration = int(request.form.get("duration", ""))
            bdate = date.fromisoformat(request.form.get("booking_date", ""))
        except ValueError:
            flash("Input tidak valid. Periksa tanggal, jam, dan durasi.")
            return redirect(url_for("customer_book"))
        table = db.execute(
            "SELECT * FROM tables WHERE id = ? AND active = 1", (table_id,)
        ).fetchone()
        errors = []
        if table is None:
            errors.append("Meja tidak ditemukan.")
        if bdate < today:
            errors.append("Tanggal booking tidak boleh sudah lewat.")
        if duration < 1 or start < OPEN_HOUR or start + duration > CLOSE_HOUR:
            errors.append(
                "Jam harus di dalam jam operasional ({:02d}:00 sampai {:02d}:00) dan durasi minimal 1 jam.".format(
                    OPEN_HOUR, CLOSE_HOUR % 24
                )
            )
        if bdate == today and start <= datetime.now().hour:
            errors.append("Jam mulai sudah lewat. Pilih jam berikutnya.")
        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for("customer_book"))

        db.execute("BEGIN IMMEDIATE")  # kunci tulis supaya tidak ada booking ganda
        try:
            if has_conflict(db, table_id, bdate.isoformat(), start, duration):
                db.rollback()
                flash("Maaf, jam itu baru saja dipesan orang lain. Pilih jam atau meja lain.")
                return redirect(url_for("customer_home", date=bdate.isoformat()))
            code = "MK" + secrets.token_hex(3).upper()
            total = table["price_per_hour"] * duration
            db.execute(
                """INSERT INTO bookings
                   (code, table_id, customer_name, customer_phone, booking_date,
                    start_hour, duration, total, status, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?, ?)""",
                (code, table_id, me["full_name"] or me["username"], me["phone"] or "",
                 bdate.isoformat(), start, duration, total, session["user_id"],
                 datetime.now().isoformat(timespec="seconds")),
            )
            db.execute(
                "UPDATE bookings SET payment_status = 'unpaid', pay_deadline = ? WHERE code = ?",
                ((datetime.now() + timedelta(minutes=PAYMENT_WINDOW_MINUTES)).isoformat(timespec="seconds"), code),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        flash("Booking dibuat. Kode booking: {} (total {}). Selesaikan pembayaran dalam {} menit.".format(
            code, rupiah(total), PAYMENT_WINDOW_MINUTES))
        new_id = db.execute("SELECT id FROM bookings WHERE code = ?", (code,)).fetchone()["id"]
        return redirect(url_for("customer_pay", booking_id=new_id))

    pre_date = today.isoformat()
    try:
        d = date.fromisoformat(request.args.get("date", ""))
        if d >= today:
            pre_date = d.isoformat()
    except ValueError:
        pass
    pre = {
        "table_id": request.args.get("table_id", type=int),
        "hour": request.args.get("hour", type=int),
        "date": pre_date,
    }
    return render_template("c_book.html", me=me, tables=tables_, pre=pre, today=today.isoformat())


@app.route("/c/my")
@customer_required
def customer_bookings():
    rows = get_db().execute(
        """SELECT b.*, t.name AS table_name FROM bookings b
           JOIN tables t ON t.id = b.table_id
           WHERE b.created_by = ?
           ORDER BY b.booking_date DESC, b.start_hour DESC""",
        (session["user_id"],),
    ).fetchall()
    return render_template("c_my.html", rows=rows, today=date.today().isoformat())


@app.route("/c/my/<int:booking_id>/cancel", methods=["POST"])
@customer_required
def customer_cancel(booking_id):
    db = get_db()
    cur = db.execute(
        """UPDATE bookings SET status = 'cancelled',
               payment_status = CASE payment_status WHEN 'paid' THEN 'refunded'
                                WHEN 'unpaid' THEN 'cancelled' ELSE payment_status END
           WHERE id = ? AND created_by = ? AND status = 'confirmed' AND booking_date >= ?""",
        (booking_id, session["user_id"], date.today().isoformat()),
    )
    db.commit()
    if cur.rowcount:
        flash("Booking dibatalkan. Jam meja tersebut kembali tersedia.")
    else:
        flash("Booking ini tidak bisa dibatalkan.")
    return redirect(url_for("customer_bookings"))


# ------------------------------------------------ pembayaran (SIMULASI)
@app.route("/c/pay/<int:booking_id>", methods=["GET", "POST"])
@customer_required
def customer_pay(booking_id):
    db = get_db()
    b = db.execute(
        """SELECT b.*, t.name AS table_name FROM bookings b
           JOIN tables t ON t.id = b.table_id
           WHERE b.id = ? AND b.created_by = ?""",
        (booking_id, session["user_id"]),
    ).fetchone()
    if b is None:
        abort(404)
    if request.method == "POST":
        method = request.form.get("method", "")
        if method not in PAY_METHODS:
            flash("Pilih metode pembayaran.")
            return redirect(url_for("customer_pay", booking_id=booking_id))
        cur = db.execute(
            """UPDATE bookings SET payment_status = 'paid', payment_method = ?, paid_at = ?
               WHERE id = ? AND created_by = ? AND status = 'confirmed' AND payment_status = 'unpaid'""",
            (PAY_METHODS[method], datetime.now().isoformat(timespec="seconds"),
             booking_id, session["user_id"]),
        )
        db.commit()
        if cur.rowcount:
            flash("Pembayaran berhasil. Booking kamu sudah terkonfirmasi.")
        else:
            flash("Booking ini tidak bisa dibayar (sudah dibayar, dibatalkan, atau waktu pembayaran habis).")
        return redirect(url_for("customer_bookings"))
    return render_template("c_pay.html", b=b, methods=PAY_METHODS)


# ------------------------------------------------ PWA (bisa di-install ke layar utama HP)
@app.route("/manifest.webmanifest")
def pwa_manifest():
    data = {
        "name": "MejaKita",
        "short_name": "MejaKita",
        "description": "Pesan meja billiard secara online.",
        "start_url": "/c",
        "scope": "/",
        "display": "standalone",
        "background_color": "#f2f4f3",
        "theme_color": "#143f30",
        "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}],
    }
    return Response(json.dumps(data), mimetype="application/manifest+json")


@app.route("/sw.js")
def pwa_service_worker():
    js = """self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener("fetch", function (e) {
  if (e.request.method !== "GET") { return; }
  e.respondWith(fetch(e.request).catch(function () {
    return new Response("Tidak ada koneksi internet. Coba lagi setelah tersambung.",
      { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }));
});
"""
    resp = Response(js, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/icon.svg")
def pwa_icon():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<rect width="512" height="512" rx="96" fill="#143f30"/>
<circle cx="256" cy="256" r="170" fill="#ffffff"/>
<circle cx="256" cy="256" r="92" fill="#1d5a44"/>
<text x="256" y="292" font-family="Arial, sans-serif" font-size="110" font-weight="700" text-anchor="middle" fill="#ffffff">8</text>
</svg>"""
    return Response(svg, mimetype="image/svg+xml")


# ------------------------------------------------------------------ template
TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}MejaKita{% endblock %}</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0b1411">
<style>
:root{--felt:#1d5a44;--felt-dark:#143f30;--wood:#8a5a2b;--bg:#f2f4f3;--ink:#1c2321;--line:#d5dbd8;--danger:#a63a2b}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5}
nav{background:var(--felt-dark);color:#fff;display:flex;align-items:center;gap:4px;padding:0 16px;flex-wrap:wrap}
nav .brand{font-weight:700;font-size:1.15rem;margin-right:16px;padding:14px 0}
nav a{color:#d9e7e1;text-decoration:none;padding:14px 10px}
nav a:hover,nav a.on{color:#fff;background:var(--felt)}
nav form{margin-left:auto}
nav button{background:none;border:1px solid #6e9a89;color:#fff;border-radius:4px;padding:6px 12px;cursor:pointer}
main{max-width:980px;margin:24px auto;padding:0 16px}
h1{margin:0 0 16px;font-size:1.5rem}
h2{font-size:1.15rem;margin:24px 0 8px}
.card{background:#fff;border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:16px}
.stat{background:#fff;border:1px solid var(--line);border-left:4px solid var(--felt);padding:12px 16px;border-radius:6px}
.stat b{display:block;font-size:1.5rem}
table{width:100%;border-collapse:collapse;background:#fff}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;font-size:.95rem}
th{background:#e8eeeb}
.scroll{overflow-x:auto}
label{display:block;font-weight:600;margin:12px 0 4px}
input,select{width:100%;padding:9px 10px;border:1px solid #aab4b0;border-radius:4px;font:inherit;background:#fff}
input:focus,select:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--wood);outline-offset:1px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.btn{background:var(--felt);color:#fff;border:0;border-radius:4px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;margin-top:16px}
.btn:hover{background:var(--felt-dark)}
.btn.small{padding:5px 10px;margin:0;font-size:.85rem}
.btn.danger{background:var(--danger)}
.flash{background:#fff4dc;border:1px solid #e3c675;padding:10px 14px;border-radius:4px;margin-bottom:12px}
.tag{padding:2px 8px;border-radius:10px;font-size:.8rem;background:#dcebe4}
.tag.cancelled{background:#f3d9d4;color:var(--danger)}
.tag.warn{background:#fff4dc;color:#7a5a00}
.free{background:#dcebe4;text-align:center}
.used{background:#8a5a2b;color:#fff;text-align:center}
.inline{display:inline-flex;gap:6px;align-items:center}
.inline input{width:120px}
.muted{color:#5d6a65;font-size:.9rem}
.login{max-width:380px;margin:12vh auto}

/* MIDNIGHT PREMIUM — admin theme */
:root{color-scheme:dark;--felt:#174b3b;--felt-dark:#0b1411;--wood:#d6b574;--bg:#0b1210;--ink:#edf3ef;--line:#293a33;--danger:#b94b4b}
body{background:radial-gradient(ellipse at 80% 0%,#142920 0%,#0b1210 48%);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
nav{position:fixed;inset:0 auto 0 0;width:252px;z-index:20;display:flex;flex-direction:column;align-items:stretch;gap:7px;flex-wrap:nowrap;padding:26px 16px;background:linear-gradient(180deg,#101d18,#0a100e);border-right:1px solid #2b4035;box-shadow:12px 0 35px rgba(0,0,0,.18)}
nav .brand{display:flex;align-items:center;gap:10px;font-family:Georgia,serif;font-size:1.55rem;letter-spacing:.02em;color:#e0c184;padding:10px 12px 28px;margin:0 0 12px;border-bottom:1px solid #293a33}
nav a{display:flex;align-items:center;gap:12px;padding:13px 14px;border:1px solid transparent;border-radius:10px;color:#aabbb2;text-decoration:none;transition:background .18s,border-color .18s,color .18s}
nav a:before{content:"";width:7px;height:7px;border:1px solid #8b9f93;border-radius:2px;flex:0 0 7px}
nav a:hover,nav a.on{background:linear-gradient(100deg,rgba(45,105,78,.35),rgba(214,181,116,.06));border-color:#345342;color:#f4e7c8}
nav a.on:before{background:#d6b574;border-color:#d6b574;box-shadow:0 0 12px #d6b57466}
nav form{margin:auto 0 0;padding-top:18px;border-top:1px solid #293a33}
nav button{width:100%;background:#182720;border:1px solid #405749;color:#e8d7b2;border-radius:9px;padding:11px 12px;cursor:pointer}
main{max-width:none;margin:0 0 0 252px;padding:38px clamp(22px,4vw,58px);min-height:100vh}
h1{font-size:clamp(1.8rem,3vw,2.5rem);font-weight:700;letter-spacing:-.035em;color:#f5f4ec;margin:0 0 8px}
h2{color:#f0eadc}
.card,.dashboard-section,.stat{background:linear-gradient(145deg,#17231d,#111a16)!important;border:1px solid #2b4035!important;border-radius:16px!important;box-shadow:0 14px 35px rgba(0,0,0,.18)!important;color:#edf3ef}
.stats{gap:16px!important;margin:28px 0 32px!important}
.stat{position:relative;overflow:hidden;padding:24px!important;border-left:1px solid #2b4035!important}
.stat:after{content:"";position:absolute;width:100px;height:100px;right:-42px;top:-48px;border-radius:50%;border:1px solid #d6b57435;box-shadow:0 0 0 12px #d6b57408,0 0 0 24px #d6b57405}
.stat .muted,.muted{color:#9aada2!important}
.stat b{color:#dfc184!important;font-size:clamp(1.6rem,2.3vw,2.2rem)!important;letter-spacing:-.035em}
.dashboard-header p{color:#9aada2!important}
.section-header{padding:22px 24px!important;border-bottom:1px solid #293a33!important}
.section-header h2{font-size:1.2rem!important;letter-spacing:-.02em}
table{background:#111a16!important;color:#e7eee9}
th,.dashboard-section th{background:#1a2b22!important;color:#ddc48f!important;border-bottom:1px solid #31473a!important}
td,.dashboard-section td{background:transparent!important;color:#d4dfd8!important;border-bottom:1px solid #26372e!important}
tr:hover td{background:#1b2b22!important}
input,select{background:#0d1712!important;color:#edf3ef!important;border:1px solid #354b3e!important;border-radius:9px!important}
input::placeholder{color:#73877b}
input:focus,select:focus,button:focus-visible,a:focus-visible{outline:2px solid #d6b574!important;outline-offset:2px}
.btn{background:linear-gradient(135deg,#dfc184,#a98549)!important;color:#111a14!important;border-radius:9px!important;box-shadow:0 6px 18px #0002}
.btn:hover{filter:brightness(1.08)}
.btn.danger{background:#8f3939!important;color:#fff!important}
.tag{background:#244b38!important;color:#bde2c9!important}.tag.cancelled{background:#4b2727!important;color:#ffb7b7!important}.tag.warn{background:#4b3c1e!important;color:#f1d18c!important}
.free{background:#1d4834!important;color:#c8efd5!important}.used{background:#6d4428!important;color:#fff0d7!important}
.flash{background:#382f1c!important;color:#f1dba9!important;border:1px solid #6d5930!important;border-radius:10px!important}
.login{background:#111a16!important}
@media(max-width:760px){nav{position:sticky;inset:auto;width:100%;height:auto;flex-direction:row;align-items:center;gap:5px;padding:10px;overflow-x:auto;border-right:0;border-bottom:1px solid #2b4035}nav .brand{font-size:1.2rem;padding:8px;margin:0;border:0;white-space:nowrap}nav a{padding:9px 10px;white-space:nowrap;font-size:.88rem}nav a:before{display:none}nav form{margin:0 0 0 auto;padding:0;border:0;flex:0 0 auto}nav button{white-space:nowrap;width:auto;padding:9px 10px}main{margin:0;padding:25px 16px;min-height:calc(100vh - 70px)}.stats{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:12px!important}.stat{padding:17px!important}}
@media(max-width:460px){.stats{grid-template-columns:1fr!important}.dashboard-header h1{font-size:1.8rem}}
</style>
</head>
<body>
{% if session.user_id and session.role != 'customer' %}
<nav>
  <span class="brand"><span aria-hidden="true">◈</span> MejaKita <small style="font:500 .62rem system-ui;letter-spacing:.18em;color:#8fa497;margin-left:auto">ADMIN</small></span>
  <a href="{{ url_for('dashboard') }}" {% if request.endpoint == 'dashboard' %}class="on"{% endif %}>Dashboard</a>
  <a href="{{ url_for('availability') }}" {% if request.endpoint == 'availability' %}class="on"{% endif %}>Ketersediaan</a>
  <a href="{{ url_for('book') }}" {% if request.endpoint == 'book' %}class="on"{% endif %}>Booking Baru</a>
  <a href="{{ url_for('bookings') }}" {% if request.endpoint == 'bookings' %}class="on"{% endif %}>Daftar Booking</a>
  {% if session.role == 'admin' %}
  <a href="{{ url_for('tables') }}" {% if request.endpoint == 'tables' %}class="on"{% endif %}>Meja &amp; Tarif</a>
  <a href="{{ url_for('report') }}" {% if request.endpoint == 'report' %}class="on"{% endif %}>Laporan</a>
  {% endif %}
  <form method="post" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <button type="submit">Keluar ({{ session.username }}, {{ session.role }})</button>
  </form>
</nav>
{% endif %}
{% block customer_nav %}{% endblock %}
<main>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block content %}{% endblock %}
</main>
<script>
if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/sw.js").catch(function () {});
  });
}
</script>
</body>
</html>""",

    "login.html": """{% extends "base.html" %}
{% block title %}Masuk - MejaKita{% endblock %}
{% block content %}
<div class="login card">
  <h1>MejaKita</h1>
  <p class="muted">Masuk ke dashboard pengelola tempat billiard.</p>
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <label for="username">Username</label>
    <input id="username" name="username" required autofocus autocomplete="username">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <button class="btn" type="submit">Masuk</button>
  </form>
  <p class="muted">Belum punya akun? <a href="{{ url_for('register') }}">Daftar sebagai pelanggan</a></p>
</div>
{% endblock %}""",

    "dashboard.html": """{% extends "base.html" %}

{% block title %}Dashboard - MejaKita{% endblock %}

{% block content %}

<style>
    .dashboard-header {
        margin-bottom: 25px;
    }

    .dashboard-header h1 {
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .dashboard-header p {
        color: #6c757d;
        margin: 0;
    }

    .stats {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 20px;
        margin-bottom: 35px;
    }

    .stat {
        background: #ffffff;
        border-radius: 12px;
        padding: 22px;
        border: 1px solid #e2e8e5;
        box-shadow: 0 3px 12px rgba(0, 0, 0, 0.06);
        transition: 0.2s;
    }

    .stat:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.09);
    }

    .stat .muted {
        display: block;
        color: #6c757d;
        font-size: 15px;
        margin-bottom: 8px;
    }

    .stat b {
        display: block;
        font-size: 30px;
        color: #0f5132;
    }

    .dashboard-section {
        background: #ffffff;
        border-radius: 12px;
        border: 1px solid #e2e8e5;
        box-shadow: 0 3px 12px rgba(0, 0, 0, 0.05);
        overflow: hidden;
    }

    .section-header {
        padding: 20px 22px;
        border-bottom: 1px solid #e2e8e5;
    }

    .section-header h2 {
        margin: 0;
        font-size: 22px;
    }

    .table-wrapper {
        overflow-x: auto;
    }

    .dashboard-section table {
        width: 100%;
        border-collapse: collapse;
        margin: 0;
    }

    .dashboard-section th {
        background: #e8f1ed;
        color: #123c2c;
        padding: 14px 16px;
        text-align: left;
        font-weight: 700;
        white-space: nowrap;
    }

    .dashboard-section td {
        padding: 14px 16px;
        border-top: 1px solid #eeeeee;
        color: #495057;
    }

    .empty-booking {
        text-align: center;
        padding: 30px !important;
        color: #6c757d;
    }

    .empty-booking strong {
        display: block;
        color: #343a40;
        margin-bottom: 5px;
    }

    @media (max-width: 900px) {
        .stats {
            grid-template-columns: repeat(2, 1fr);
        }
    }

    @media (max-width: 600px) {
        .stats {
            grid-template-columns: 1fr;
        }

        .dashboard-header h1 {
            font-size: 27px;
        }

        .stat b {
            font-size: 26px;
        }
    }
</style>

<div class="dashboard-header">
    <h1>Dashboard</h1>
    <p>Ringkasan aktivitas MejaKita hari ini.</p>
</div>

<div class="stats">

    <div class="stat">
        <span class="muted">Meja aktif</span>
        <b>{{ stats.tables }}</b>
    </div>

    <div class="stat">
        <span class="muted">Booking hari ini</span>
        <b>{{ stats.today_count }}</b>
    </div>

    <div class="stat">
        <span class="muted">Pendapatan hari ini</span>
        <b>Rp{{ "{:,.0f}".format(stats.today_revenue).replace(",", ".") }}</b>
    </div>

    <div class="stat">
        <span class="muted">Total booking aktif</span>
        <b>{{ stats.all_count }}</b>
    </div>

</div>

<div class="dashboard-section">

    <div class="section-header">
        <h2>Booking Mendatang</h2>
    </div>

    <div class="table-wrapper">

        <table>
            <thead>
                <tr>
                    <th>Kode</th>
                    <th>Pelanggan</th>
                    <th>Meja</th>
                    <th>Tanggal</th>
                    <th>Jam</th>
                    <th>Total</th>
                </tr>
            </thead>

            <tbody>

                {% for b in upcoming %}

                <tr>
                    <td><strong>{{ b.code }}</strong></td>
                    <td>{{ b.customer_name }}</td>
                    <td>{{ b.table_name }}</td>
                    <td>{{ b.booking_date }}</td>
                    <td>
                        {{ b.start_hour }} -
                        {{ b.start_hour + b.duration }} jam
                    </td>
                    <td>Rp{{ "{:,.0f}".format(b.total).replace(",", ".") }}</td>
                </tr>

                {% else %}

                <tr>
                    <td colspan="6" class="empty-booking">
                        <strong>Belum ada booking mendatang</strong>
                        Buat booking pertama melalui menu <b>Booking Baru</b>.
                    </td>
                </tr>

                {% endfor %}

            </tbody>
        </table>

    </div>

</div>

{% endblock %}""",

    "tables.html": """{% extends "base.html" %}
{% block title %}Meja &amp; Tarif - MejaKita{% endblock %}
{% block content %}
<h1>Meja &amp; Tarif</h1>
<div class="card">
  <form method="post" class="row">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <input type="hidden" name="action" value="add">
    <div><label for="name">Nama meja</label><input id="name" name="name" required></div>
    <div><label for="price">Tarif per jam (Rp)</label><input id="price" name="price_per_hour" type="number" min="1" required></div>
    <div><button class="btn" type="submit">Tambah meja</button></div>
  </form>
</div>
<div class="scroll">
<table>
  <tr><th>Meja</th><th>Tarif per jam</th><th>Ubah tarif</th><th>Status</th></tr>
  {% for t in rows %}
  <tr>
    <td>{{ t.name }}</td>
    <td>{{ t.price_per_hour|rp }}</td>
    <td>
      <form method="post" class="inline">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="price">
        <input type="hidden" name="table_id" value="{{ t.id }}">
        <input name="price_per_hour" type="number" min="1" required aria-label="Tarif baru {{ t.name }}">
        <button class="btn small" type="submit">Simpan</button>
      </form>
    </td>
    <td>
      <form method="post" class="inline">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="toggle">
        <input type="hidden" name="table_id" value="{{ t.id }}">
        <span class="tag {% if not t.active %}cancelled{% endif %}">{{ 'Aktif' if t.active else 'Nonaktif' }}</span>
        <button class="btn small" type="submit">{{ 'Nonaktifkan' if t.active else 'Aktifkan' }}</button>
      </form>
    </td>
  </tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",

    "availability.html": """{% extends "base.html" %}
{% block title %}Ketersediaan - MejaKita{% endblock %}
{% block content %}
<h1>Ketersediaan meja</h1>
<form method="get" class="card row">
  <div><label for="date">Tanggal</label><input id="date" name="date" type="date" value="{{ chosen }}"></div>
  <div><button class="btn" type="submit">Lihat</button></div>
</form>
<p class="muted">Hijau = kosong, cokelat = sudah dibooking.</p>
<div class="scroll">
<table>
  <tr><th>Meja</th>{% for h in hours %}<th>{{ h|jam }}</th>{% endfor %}</tr>
  {% for t in tables %}
  <tr><td>{{ t.name }}</td>
    {% for h in hours %}
      {% if h in busy[t.id] %}<td class="used">Terisi</td>{% else %}<td class="free">Kosong</td>{% endif %}
    {% endfor %}
  </tr>
  {% else %}
  <tr><td class="muted">Belum ada meja aktif. Tambahkan di menu Meja &amp; Tarif.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",

    "book.html": """{% extends "base.html" %}
{% block title %}Booking Baru - MejaKita{% endblock %}
{% block content %}
<h1>Booking baru</h1>
<div class="card">
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <div class="row">
    <div><label for="customer_name">Nama pelanggan</label><input id="customer_name" name="customer_name" required></div>
    <div><label for="customer_phone">No. WhatsApp</label><input id="customer_phone" name="customer_phone" inputmode="tel" required placeholder="contoh: 081234567890"></div>
  </div>
  <div class="row">
    <div><label for="table_id">Meja</label>
      <select id="table_id" name="table_id" required>
        {% for t in tables %}<option value="{{ t.id }}">{{ t.name }} ({{ t.price_per_hour|rp }}/jam)</option>{% endfor %}
      </select></div>
    <div><label for="booking_date">Tanggal</label><input id="booking_date" name="booking_date" type="date" min="{{ today }}" value="{{ today }}" required></div>
    <div><label for="start_hour">Jam mulai</label>
      <select id="start_hour" name="start_hour">
        {% for h in range(open_hour, close_hour) %}<option value="{{ h }}">{{ h|jam }}</option>{% endfor %}
      </select></div>
    <div><label for="duration">Durasi (jam)</label><input id="duration" name="duration" type="number" min="1" max="{{ close_hour - open_hour }}" value="1" required></div>
  </div>
  <button class="btn" type="submit">Simpan booking</button>
</form>
</div>
{% endblock %}""",

    "bookings.html": """{% extends "base.html" %}
{% block title %}Daftar Booking - MejaKita{% endblock %}
{% block content %}
<h1>Daftar booking</h1>
<div class="scroll">
<table>
  <tr><th>Kode</th><th>Pelanggan</th><th>Meja</th><th>Tanggal</th><th>Jam</th><th>Total</th><th>Status</th><th></th></tr>
  {% for b in rows %}
  <tr>
    <td>{{ b.code }}</td><td>{{ b.customer_name }}<br><span class="muted">{{ b.customer_phone }}</span></td>
    <td>{{ b.table_name }}</td><td>{{ b.booking_date }}</td>
    <td>{{ b.start_hour|jam }} - {{ (b.start_hour + b.duration)|jam }}</td>
    <td>{{ b.total|rp }}</td>
    <td><span class="tag {% if b.status == 'cancelled' %}cancelled{% endif %}">{{ 'Dikonfirmasi' if b.status == 'confirmed' else 'Dibatalkan' }}</span></td>
    <td>{% if b.status == 'confirmed' %}
      <form method="post" action="{{ url_for('cancel_booking', booking_id=b.id) }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <button class="btn small danger" type="submit">Batalkan</button>
      </form>{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="8" class="muted">Belum ada booking. Buat yang pertama lewat menu Booking Baru.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",

    "report.html": """{% extends "base.html" %}
{% block title %}Laporan - MejaKita{% endblock %}
{% block content %}
<h1>Laporan pendapatan</h1>
<form method="get" class="card row">
  <div><label for="from">Dari tanggal</label><input id="from" name="from" type="date" value="{{ d_from }}"></div>
  <div><label for="to">Sampai tanggal</label><input id="to" name="to" type="date" value="{{ d_to }}"></div>
  <div><button class="btn" type="submit">Tampilkan</button></div>
</form>
<div class="stats">
  <div class="stat"><span class="muted">Total pendapatan (lunas)</span><b>{{ total|rp }}</b></div>
  <div class="stat"><span class="muted">Booking lunas</span><b>{{ rows|length }}</b></div>
  <div class="stat"><span class="muted">Booking dibatalkan</span><b>{{ cancelled }}</b></div>
</div>
<h2>Per meja</h2>
<div class="scroll">
<table>
  <tr><th>Meja</th><th>Jumlah booking</th><th>Total jam</th><th>Pendapatan</th></tr>
  {% for p in per_table %}
  <tr><td>{{ p.name }}</td><td>{{ p.n }}</td><td>{{ p.hours }}</td><td>{{ p.revenue|rp }}</td></tr>
  {% else %}
  <tr><td colspan="4" class="muted">Tidak ada transaksi pada rentang tanggal ini.</td></tr>
  {% endfor %}
</table>
</div>
<h2>Rincian transaksi</h2>
<div class="scroll">
<table>
  <tr><th>Kode</th><th>Tanggal</th><th>Meja</th><th>Pelanggan</th><th>Durasi</th><th>Total</th></tr>
  {% for r in rows %}
  <tr><td>{{ r.code }}</td><td>{{ r.booking_date }}</td><td>{{ r.table_name }}</td><td>{{ r.customer_name }}</td><td>{{ r.duration }} jam</td><td>{{ r.total|rp }}</td></tr>
  {% else %}
  <tr><td colspan="6" class="muted">Tidak ada transaksi pada rentang tanggal ini.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",
}

TEMPLATES.update({
    "cbase.html": """{% extends "base.html" %}
{% block customer_nav %}
<style>
.slots{display:flex;flex-wrap:wrap;gap:8px}
.slot{display:inline-block;min-width:70px;text-align:center;padding:10px 6px;border-radius:6px;font-weight:600;font-size:.9rem;text-decoration:none}
a.slot.free{background:#dcebe4;color:#143f30;border:1px solid #1d5a44}
a.slot.free:hover{background:#1d5a44;color:#fff}
.slot.taken{background:#8a5a2b;color:#fff}
.slot.past{background:#e4e7e6;color:#8a948f}
.table-card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:14px}
.table-card h3{margin:0}
.table-card p{margin:2px 0 12px}
</style>
<nav>
  <span class="brand">MejaKita</span>
  <a href="{{ url_for('customer_home') }}" {% if request.endpoint == 'customer_home' %}class="on"{% endif %}>Cari Meja</a>
  <a href="{{ url_for('customer_book') }}" {% if request.endpoint == 'customer_book' %}class="on"{% endif %}>Booking</a>
  <a href="{{ url_for('customer_bookings') }}" {% if request.endpoint == 'customer_bookings' %}class="on"{% endif %}>Booking Saya</a>
  <form method="post" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <button type="submit">Keluar ({{ session.username }})</button>
  </form>
</nav>
{% endblock %}""",

    "register.html": """{% extends "base.html" %}
{% block title %}Daftar - MejaKita{% endblock %}
{% block content %}
<div class="login card">
  <h1>Daftar akun MejaKita</h1>
  <p class="muted">Buat akun untuk memesan meja billiard secara online.</p>
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <label for="full_name">Nama lengkap</label>
    <input id="full_name" name="full_name" value="{{ form.get('full_name', '') }}" required autocomplete="name">
    <label for="phone">No. WhatsApp</label>
    <input id="phone" name="phone" value="{{ form.get('phone', '') }}" inputmode="tel" required placeholder="contoh: 081234567890" autocomplete="tel">
    <label for="username">Username</label>
    <input id="username" name="username" value="{{ form.get('username', '') }}" required autocomplete="username">
    <label for="password">Password (minimal {{ min_password }} karakter)</label>
    <input id="password" name="password" type="password" minlength="{{ min_password }}" required autocomplete="new-password">
    <label for="confirm">Ulangi password</label>
    <input id="confirm" name="confirm" type="password" required autocomplete="new-password">
    <button class="btn" type="submit">Buat akun</button>
  </form>
  <p class="muted">Sudah punya akun? <a href="{{ url_for('login') }}">Masuk</a></p>
</div>
{% endblock %}""",

    "c_home.html": """{% extends "cbase.html" %}
{% block title %}Cari Meja - MejaKita{% endblock %}
{% block content %}
<h1>Cari meja billiard</h1>
{% if venue %}<p class="muted">{{ venue.name }}{% if venue.address %}, {{ venue.address }}{% endif %}. Buka {{ open_hour|jam }} sampai {{ close_hour|jam }}.</p>{% endif %}
<form method="get" class="card row">
  <div><label for="date">Tanggal</label><input id="date" name="date" type="date" min="{{ today }}" value="{{ chosen }}"></div>
  <div><button class="btn" type="submit">Lihat jam kosong</button></div>
</form>
<p class="muted">Ketuk jam hijau untuk memesan. Cokelat = sudah dipesan, abu-abu = sudah lewat.</p>
{% for t in tables %}
<div class="table-card">
  <h3>{{ t.name }}</h3>
  <p class="muted">{{ t.price_per_hour|rp }} per jam</p>
  <div class="slots">
    {% for h in hours %}
      {% if h in busy[t.id] %}<span class="slot taken">{{ h|jam }}</span>
      {% elif is_today and h <= now_hour %}<span class="slot past">{{ h|jam }}</span>
      {% else %}<a class="slot free" href="{{ url_for('customer_book', table_id=t.id, date=chosen, hour=h) }}">{{ h|jam }}</a>{% endif %}
    {% endfor %}
  </div>
</div>
{% else %}
<p class="muted">Belum ada meja yang tersedia.</p>
{% endfor %}
{% endblock %}""",

    "c_book.html": """{% extends "cbase.html" %}
{% block title %}Booking - MejaKita{% endblock %}
{% block content %}
<h1>Pesan meja</h1>
<div class="card">
<p class="muted">Atas nama <b>{{ me.full_name or me.username }}</b>{% if me.phone %} ({{ me.phone }}){% endif %}</p>
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <div class="row">
    <div><label for="table_id">Meja</label>
      <select id="table_id" name="table_id" required>
        {% for t in tables %}<option value="{{ t.id }}" {% if t.id == pre.table_id %}selected{% endif %}>{{ t.name }} ({{ t.price_per_hour|rp }}/jam)</option>{% endfor %}
      </select></div>
    <div><label for="booking_date">Tanggal</label><input id="booking_date" name="booking_date" type="date" min="{{ today }}" value="{{ pre.date }}" required></div>
    <div><label for="start_hour">Jam mulai</label>
      <select id="start_hour" name="start_hour">
        {% for h in range(open_hour, close_hour) %}<option value="{{ h }}" {% if h == pre.hour %}selected{% endif %}>{{ h|jam }}</option>{% endfor %}
      </select></div>
    <div><label for="duration">Durasi (jam)</label><input id="duration" name="duration" type="number" min="1" max="{{ close_hour - open_hour }}" value="1" required></div>
  </div>
  <button class="btn" type="submit">Pesan sekarang</button>
</form>
</div>
{% endblock %}""",

    "c_my.html": """{% extends "cbase.html" %}
{% block title %}Booking Saya - MejaKita{% endblock %}
{% block content %}
<h1>Booking saya</h1>
<div class="scroll">
<table>
  <tr><th>Kode</th><th>Meja</th><th>Tanggal</th><th>Jam</th><th>Total</th><th>Status</th><th></th></tr>
  {% for b in rows %}
  <tr>
    <td>{{ b.code }}</td><td>{{ b.table_name }}</td><td>{{ b.booking_date }}</td>
    <td>{{ b.start_hour|jam }} - {{ (b.start_hour + b.duration)|jam }}</td>
    <td>{{ b.total|rp }}</td>
    <td><span class="tag {% if b.status == 'cancelled' %}cancelled{% endif %}">{{ 'Dikonfirmasi' if b.status == 'confirmed' else 'Dibatalkan' }}</span></td>
    <td>{% if b.status == 'confirmed' and b.booking_date >= today %}
      <form method="post" action="{{ url_for('customer_cancel', booking_id=b.id) }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <button class="btn small danger" type="submit">Batalkan</button>
      </form>{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="7" class="muted">Kamu belum punya booking. Mulai dari menu Cari Meja.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",
})

TEMPLATES.update({
    "c_pay.html": """{% extends "cbase.html" %}
{% block title %}Pembayaran - MejaKita{% endblock %}
{% block content %}
<h1>Pembayaran</h1>
<div class="card">
  <p><b>{{ b.code }}</b>, {{ b.table_name }}, {{ b.booking_date }}, {{ b.start_hour|jam }} - {{ (b.start_hour + b.duration)|jam }}</p>
  <p>Total bayar: <b>{{ b.total|rp }}</b></p>
  {% if b.payment_status == 'unpaid' and b.status == 'confirmed' %}
    <p class="muted">Selesaikan sebelum {{ b.pay_deadline|replace('T', ' ') }}. Jika terlambat, booking dibatalkan otomatis.</p>
    <form method="post">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      {% for key, label in methods.items() %}
      <label style="font-weight:400"><input type="radio" name="method" value="{{ key }}" required style="width:auto;margin-right:8px">{{ label }}</label>
      {% endfor %}
      <button class="btn" type="submit">Bayar sekarang</button>
    </form>
  {% else %}
    <p>Status pembayaran:
      <span class="tag {% if b.payment_status in ('expired', 'cancelled', 'refunded') %}cancelled{% elif b.payment_status == 'unpaid' %}warn{% endif %}">{{ b.payment_status|paylabel }}</span></p>
    {% if b.payment_method %}<p class="muted">Metode: {{ b.payment_method }}</p>{% endif %}
  {% endif %}
  <p><a href="{{ url_for('customer_bookings') }}">Kembali ke Booking Saya</a></p>
</div>
{% endblock %}""",

    "c_my.html": """{% extends "cbase.html" %}
{% block title %}Booking Saya - MejaKita{% endblock %}
{% block content %}
<h1>Booking saya</h1>
<div class="scroll">
<table>
  <tr><th>Kode</th><th>Meja</th><th>Tanggal</th><th>Jam</th><th>Total</th><th>Status</th><th>Pembayaran</th><th></th></tr>
  {% for b in rows %}
  <tr>
    <td>{{ b.code }}</td><td>{{ b.table_name }}</td><td>{{ b.booking_date }}</td>
    <td>{{ b.start_hour|jam }} - {{ (b.start_hour + b.duration)|jam }}</td>
    <td>{{ b.total|rp }}</td>
    <td><span class="tag {% if b.status == 'cancelled' %}cancelled{% endif %}">{{ 'Dikonfirmasi' if b.status == 'confirmed' else 'Dibatalkan' }}</span></td>
    <td><span class="tag {% if b.payment_status in ('expired', 'cancelled', 'refunded') %}cancelled{% elif b.payment_status == 'unpaid' %}warn{% endif %}">{{ b.payment_status|paylabel }}</span></td>
    <td>
      {% if b.status == 'confirmed' and b.payment_status == 'unpaid' %}
        <a class="btn small" style="display:inline-block;text-decoration:none" href="{{ url_for('customer_pay', booking_id=b.id) }}">Bayar</a>
      {% endif %}
      {% if b.status == 'confirmed' and b.booking_date >= today %}
      <form method="post" action="{{ url_for('customer_cancel', booking_id=b.id) }}" style="display:inline">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <button class="btn small danger" type="submit">Batalkan</button>
      </form>{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="8" class="muted">Kamu belum punya booking. Mulai dari menu Cari Meja.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",

    "bookings.html": """{% extends "base.html" %}
{% block title %}Daftar Booking - MejaKita{% endblock %}
{% block content %}
<h1>Daftar booking</h1>
<div class="scroll">
<table>
  <tr><th>Kode</th><th>Pelanggan</th><th>Meja</th><th>Tanggal</th><th>Jam</th><th>Total</th><th>Status</th><th>Pembayaran</th><th></th></tr>
  {% for b in rows %}
  <tr>
    <td>{{ b.code }}</td><td>{{ b.customer_name }}<br><span class="muted">{{ b.customer_phone }}</span></td>
    <td>{{ b.table_name }}</td><td>{{ b.booking_date }}</td>
    <td>{{ b.start_hour|jam }} - {{ (b.start_hour + b.duration)|jam }}</td>
    <td>{{ b.total|rp }}</td>
    <td><span class="tag {% if b.status == 'cancelled' %}cancelled{% endif %}">{{ 'Dikonfirmasi' if b.status == 'confirmed' else 'Dibatalkan' }}</span></td>
    <td><span class="tag {% if b.payment_status in ('expired', 'cancelled', 'refunded') %}cancelled{% elif b.payment_status == 'unpaid' %}warn{% endif %}">{{ b.payment_status|paylabel }}</span>
        <br><span class="muted">{{ b.payment_method or 'Tunai' }}</span></td>
    <td>{% if b.status == 'confirmed' %}
      <form method="post" action="{{ url_for('cancel_booking', booking_id=b.id) }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <button class="btn small danger" type="submit">Batalkan</button>
      </form>{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="9" class="muted">Belum ada booking. Buat yang pertama lewat menu Booking Baru.</td></tr>
  {% endfor %}
</table>
</div>
{% endblock %}""",
})

TEMPLATES.update({
    "auth_base.html": """{% extends "base.html" %}
{% block content %}
<style>
@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Inter:wght@400;500;600&display=swap');
main{max-width:none;margin:0;padding:0}
.auth{--gold:#c9a86a;--cream:#f4efe4;--muted:#9db0a7;display:grid;grid-template-columns:1.1fr .9fr;min-height:100vh;min-height:100dvh;background:#0e1f19;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.auth-cover{position:relative;overflow:hidden;background:#0a1712}
.auth-photo{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;transform:scale(1.08);filter:blur(5px) brightness(.8) saturate(1.1)}
.auth-veil{position:absolute;inset:0;background:radial-gradient(120% 90% at 25% 35%,rgba(0,0,0,.05),rgba(0,0,0,.65) 100%),linear-gradient(180deg,rgba(0,0,0,.5) 0%,rgba(0,0,0,.1) 38%,rgba(0,0,0,.9) 100%)}
.auth-cover::after{content:"";position:absolute;inset:18px;border:1px solid rgba(201,168,106,.35);pointer-events:none;z-index:3}
.auth-cover-inner{position:relative;z-index:2;height:100%;min-height:inherit;display:flex;flex-direction:column;justify-content:space-between;padding:52px 56px}
.brand{display:flex;align-items:center;gap:12px;color:var(--cream);font-family:"Cormorant Garamond",Georgia,"Times New Roman",serif;font-size:1.7rem;font-weight:700;letter-spacing:.04em}
.eyebrow{margin:0 0 14px;color:var(--gold);font-size:.74rem;letter-spacing:.24em;text-transform:uppercase;font-weight:600}
.auth-cover h2{margin:0 0 26px;max-width:15em;color:var(--cream);font-family:"Cormorant Garamond",Georgia,"Times New Roman",serif;font-weight:600;font-size:clamp(2rem,3.5vw,3.2rem);line-height:1.08}
.perks{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.perks li{display:flex;align-items:center;gap:12px;color:rgba(244,239,228,.88);font-size:.95rem}
.perks li::before{content:"";flex:none;width:6px;height:6px;background:var(--gold);transform:rotate(45deg)}
.auth-panel{display:flex;align-items:center;justify-content:center;padding:48px 28px;background:radial-gradient(900px 520px at 100% 0%,rgba(201,168,106,.11),transparent 60%),linear-gradient(180deg,#0c1a14 0%,#040907 100%)}
.auth-card{width:100%;max-width:400px;color:var(--cream)}
.auth-card h1{margin:0 0 8px;color:var(--cream);font-family:"Cormorant Garamond",Georgia,"Times New Roman",serif;font-weight:600;font-size:2.5rem;line-height:1.05}
.auth-card .lead{margin:0 0 26px;color:var(--muted);font-size:.98rem}
.auth-card label{display:block;margin:20px 0 4px;color:var(--gold);font-size:.7rem;font-weight:600;letter-spacing:.16em;text-transform:uppercase}
.auth-card input{width:100%;padding:10px 2px;background:transparent;border:0;border-bottom:1px solid rgba(244,239,228,.3);border-radius:0;color:var(--cream);font:inherit;font-size:1rem}
.auth-card input::placeholder{color:rgba(157,176,167,.6)}
.auth-card input:focus{outline:none;border-bottom-color:var(--gold);box-shadow:0 1px 0 0 var(--gold)}
.auth-card input:-webkit-autofill{-webkit-text-fill-color:var(--cream);box-shadow:0 0 0 1000px #0e1f19 inset;caret-color:var(--cream)}
.btn-gold{display:block;width:100%;margin-top:34px;padding:14px;border:0;border-radius:2px;background:linear-gradient(135deg,#d9bc80,#ad8a4c);color:#10231b;font:inherit;font-size:.85rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;cursor:pointer}
.btn-gold:hover{filter:brightness(1.08)}
.btn-gold:focus-visible{outline:2px solid var(--cream);outline-offset:3px}
.auth-alt{margin:26px 0 0;color:var(--muted);font-size:.95rem}
.auth-alt a{color:var(--gold);text-underline-offset:3px}
#auth-flash:not(:empty){margin-bottom:22px}
#auth-flash .flash{margin:0 0 10px;padding:10px 14px;background:rgba(201,168,106,.1);border:1px solid rgba(201,168,106,.45);border-radius:2px;color:var(--cream);font-size:.92rem}
@media (max-width:900px){
  .auth{grid-template-columns:1fr}
  .auth-cover{min-height:240px}
  .auth-cover-inner{padding:32px 28px}
  .auth-cover h2{font-size:1.6rem;margin:0}
  .eyebrow,.perks{display:none}
  .auth-panel{padding:36px 22px 48px;align-items:flex-start}
}
</style>
<div class="auth">
  <section class="auth-cover" aria-label="MejaKita">
    <img class="auth-photo" src="{{ url_for('static', filename='login_cover.jpg') }}" alt="">
    <div class="auth-veil"></div>
    <div class="auth-cover-inner">
      <div class="brand">
        <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="15" fill="none" stroke="#c9a86a" stroke-width="1.5"/><circle cx="16" cy="16" r="8.5" fill="#c9a86a"/><text x="16" y="20" text-anchor="middle" font-size="11" font-weight="700" fill="#0d1b16" font-family="Georgia, serif">8</text></svg>
        <span>MejaKita</span>
      </div>
      <div class="hero">
        <p class="eyebrow">Reservasi meja billiard</p>
        <h2>Fokus ke permainanmu, satu meja, satu game seru.</h2>
        <ul class="perks">
          <li>Ketersediaan jam terlihat real-time</li>
          <li>Booking dan pembayaran selesai dalam hitungan menit</li>
          <li>Tinggal datang dan main, mejamu sudah aman</li>
        </ul>
      </div>
    </div>
  </section>
  <section class="auth-panel">
    <div class="auth-card">
      <div id="auth-flash"></div>
      {% block auth_form %}{% endblock %}
    </div>
  </section>
</div>
<script>
(function () {
  var box = document.getElementById("auth-flash");
  if (!box) { return; }
  document.querySelectorAll("main > .flash").forEach(function (f) { box.appendChild(f); });
})();
</script>
{% endblock %}""",

    "login.html": """{% extends "auth_base.html" %}
{% block title %}Masuk - MejaKita{% endblock %}
{% block auth_form %}
<h1>Selamat datang</h1>
<p class="lead">Masuk untuk memesan meja atau mengelola tempat billiard.</p>
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <label for="username">Username</label>
  <input id="username" name="username" required autofocus autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <button class="btn-gold" type="submit">Masuk</button>
</form>
<p class="auth-alt">Belum punya akun? <a href="{{ url_for('register') }}">Daftar sebagai pelanggan</a></p>
{% endblock %}""",

    "register.html": """{% extends "auth_base.html" %}
{% block title %}Daftar - MejaKita{% endblock %}
{% block auth_form %}
<h1>Buat akun</h1>
<p class="lead">Daftar sekali, lalu pesan meja kapan saja.</p>
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <label for="full_name">Nama lengkap</label>
  <input id="full_name" name="full_name" value="{{ form.get('full_name', '') }}" required autocomplete="name">
  <label for="phone">No. WhatsApp</label>
  <input id="phone" name="phone" value="{{ form.get('phone', '') }}" inputmode="tel" required placeholder="contoh: 081234567890" autocomplete="tel">
  <label for="username">Username</label>
  <input id="username" name="username" value="{{ form.get('username', '') }}" required autocomplete="username">
  <label for="password">Password (minimal {{ min_password }} karakter)</label>
  <input id="password" name="password" type="password" minlength="{{ min_password }}" required autocomplete="new-password">
  <label for="confirm">Ulangi password</label>
  <input id="confirm" name="confirm" type="password" required autocomplete="new-password">
  <button class="btn-gold" type="submit">Buat akun</button>
</form>
<p class="auth-alt">Sudah punya akun? <a href="{{ url_for('login') }}">Masuk</a></p>
{% endblock %}""",
})

app.jinja_loader = DictLoader(TEMPLATES)

init_db()

if __name__ == "__main__":
    app.run(debug=False)