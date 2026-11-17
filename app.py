import os, sqlite3, secrets
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("RUANG_DB", os.path.join(APP_DIR, "ruang.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("RUANG_SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("RUANG_SECRET_KEY belum diatur. Salin .env.example menjadi .env dan isi secret key.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

ROLES = {
    "owner": "Owner / Super Admin",
    "content": "Admin Konten",
    "event": "Admin Event",
    "community": "Admin Komunitas",
    "media": "Admin Media"
}
PERMISSIONS = {
    "owner": {"dashboard","articles","events","registrations","programs","members","admins","settings"},
    "content": {"dashboard","articles"},
    "event": {"dashboard","events","registrations"},
    "community": {"dashboard","members","programs"},
    "media": {"dashboard","media"}
}

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS articles(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL,
      excerpt TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL,
      event_date TEXT NOT NULL, event_time TEXT NOT NULL, location TEXT NOT NULL,
      description TEXT NOT NULL, capacity INTEGER NOT NULL DEFAULT 100,
      status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS registrations(
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER,
      name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL,
      note TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'baru',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS programs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'aktif',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS members(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL,
      phone TEXT NOT NULL, interest TEXT NOT NULL, note TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'baru', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

def current_user():
    if "user_id" not in session: return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()

def allowed(permission):
    user = current_user()
    return bool(user and permission in PERMISSIONS.get(user["role"], set()))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user(): return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def permission_required(permission):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if not allowed(permission): abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.before_request
def csrf_guard():
    if request.method == "POST":
        token = session.get("_csrf")
        submitted = request.form.get("_csrf")
        if not token or not submitted or not secrets.compare_digest(token, submitted):
            abort(400, "Permintaan tidak valid atau sesi kedaluwarsa. Muat ulang halaman.")

@app.context_processor
def inject_globals():
    user = current_user()
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return {"admin_user": user, "csrf": session["_csrf"], "roles": ROLES, "allowed": allowed}

@app.route("/")
def home():
    events = db().execute("SELECT * FROM events WHERE status='open' ORDER BY event_date LIMIT 3").fetchall()
    articles = db().execute("SELECT * FROM articles WHERE status='published' ORDER BY id DESC LIMIT 3").fetchall()
    return render_template("public.html", events=events, articles=articles)

@app.route("/daftar", methods=["POST"])
def register():
    name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
    phone=request.form.get("phone","").strip(); interest=request.form.get("interest","").strip()
    note=request.form.get("note","").strip()
    if not all([name,email,phone,interest]) or "@" not in email:
        flash("Mohon lengkapi data pendaftaran dengan benar.", "error")
        return redirect(url_for("home"))
    db().execute("INSERT INTO members(name,email,phone,interest,note) VALUES(?,?,?,?,?)",(name,email,phone,interest,note))
    db().commit()
    flash("Pendaftaran minat bergabung berhasil dikirim. Terima kasih!", "success")
    return redirect(url_for("home"))

@app.route("/daftar-event", methods=["POST"])
def event_register():
    event_id=request.form.get("event_id") or None
    name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
    phone=request.form.get("phone","").strip(); note=request.form.get("note","").strip()
    if not all([name,email,phone]) or "@" not in email:
        flash("Nama, email, dan nomor WhatsApp wajib diisi.", "error"); return redirect(url_for("home"))
    if event_id:
        event=db().execute("SELECT * FROM events WHERE id=? AND status='open'",(event_id,)).fetchone()
        if not event:
            flash("Event tidak ditemukan atau pendaftaran sudah ditutup.","error"); return redirect(url_for("home"))
        count=db().execute("SELECT COUNT(*) n FROM registrations WHERE event_id=?",(event_id,)).fetchone()["n"]
        if count >= event["capacity"]:
            flash("Kuota event sudah penuh.","error"); return redirect(url_for("home"))
    db().execute("INSERT INTO registrations(event_id,name,email,phone,note) VALUES(?,?,?,?,?)",(event_id,name,email,phone,note))
    db().commit(); flash("Pendaftaran event berhasil dikirim.","success")
    return redirect(url_for("home"))

@app.route("/admin/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        user=db().execute("SELECT * FROM users WHERE email=? AND active=1",(email,)).fetchone()
        if user and check_password_hash(user["password_hash"],password):
            session.clear(); session["user_id"]=user["id"]; session["_csrf"]=secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        flash("Email atau kata sandi tidak sesuai.", "error")
    return render_template("login.html")

@app.route("/admin/logout", methods=["POST"])
@login_required
def logout():
    session.clear(); flash("Anda telah keluar dari dashboard.", "success")
    return redirect(url_for("login"))

@app.route("/admin")
@permission_required("dashboard")
def dashboard():
    conn=db()
    counts={
      "members":conn.execute("SELECT COUNT(*) n FROM members").fetchone()["n"],
      "events":conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"],
      "articles":conn.execute("SELECT COUNT(*) n FROM articles").fetchone()["n"],
      "registrations":conn.execute("SELECT COUNT(*) n FROM registrations").fetchone()["n"]
    }
    recent=conn.execute("SELECT name,email,created_at FROM members ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html", counts=counts, recent=recent, page="dashboard")

@app.route("/admin/artikel", methods=["GET","POST"])
@permission_required("articles")
def articles():
    if request.method=="POST":
        title=request.form.get("title","").strip(); category=request.form.get("category","").strip()
        excerpt=request.form.get("excerpt","").strip(); body=request.form.get("body","").strip()
        status=request.form.get("status","draft")
        if title and category and excerpt and body and status in ("draft","published"):
            db().execute("INSERT INTO articles(title,category,excerpt,body,status) VALUES(?,?,?,?,?)",(title,category,excerpt,body,status)); db().commit()
            flash("Artikel berhasil disimpan.","success")
        else: flash("Lengkapi seluruh kolom artikel.","error")
        return redirect(url_for("articles"))
    rows=db().execute("SELECT * FROM articles ORDER BY id DESC").fetchall()
    return render_template("list.html", page="articles", title="Kelola Artikel", rows=rows)

@app.route("/admin/artikel/<int:item_id>/hapus", methods=["POST"])
@permission_required("articles")
def delete_article(item_id):
    db().execute("DELETE FROM articles WHERE id=?",(item_id,)); db().commit()
    flash("Artikel dihapus.","success"); return redirect(url_for("articles"))

@app.route("/admin/event", methods=["GET","POST"])
@permission_required("events")
def events():
    if request.method=="POST":
        fields=[request.form.get(k,"").strip() for k in ("title","category","event_date","event_time","location","description")]
        try: capacity=max(1,int(request.form.get("capacity","100")))
        except ValueError: capacity=100
        if all(fields):
            db().execute("INSERT INTO events(title,category,event_date,event_time,location,description,capacity) VALUES(?,?,?,?,?,?,?)",(*fields,capacity)); db().commit()
            flash("Event berhasil dibuat.","success")
        else: flash("Lengkapi seluruh kolom event.","error")
        return redirect(url_for("events"))
    rows=db().execute("SELECT e.*, (SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id) AS total FROM events e ORDER BY event_date DESC").fetchall()
    return render_template("list.html",page="events",title="Kelola Event",rows=rows)

@app.route("/admin/event/<int:item_id>/status", methods=["POST"])
@permission_required("events")
def event_status(item_id):
    status=request.form.get("status","open")
    if status not in ("open","closed"): abort(400)
    db().execute("UPDATE events SET status=? WHERE id=?",(status,item_id)); db().commit()
    flash("Status event diperbarui.","success"); return redirect(url_for("events"))

@app.route("/admin/pendaftaran")
@permission_required("registrations")
def registrations():
    rows=db().execute("SELECT r.*,e.title event_title FROM registrations r LEFT JOIN events e ON e.id=r.event_id ORDER BY r.id DESC").fetchall()
    return render_template("list.html",page="registrations",title="Pendaftaran Event",rows=rows)

@app.route("/admin/program", methods=["GET","POST"])
@permission_required("programs")
def programs():
    if request.method=="POST":
        title=request.form.get("title","").strip(); category=request.form.get("category","").strip(); description=request.form.get("description","").strip()
        if title and category and description:
            db().execute("INSERT INTO programs(title,category,description) VALUES(?,?,?)",(title,category,description)); db().commit(); flash("Program ditambahkan.","success")
        else: flash("Lengkapi data program.","error")
        return redirect(url_for("programs"))
    rows=db().execute("SELECT * FROM programs ORDER BY id DESC").fetchall()
    return render_template("list.html",page="programs",title="Program & Layanan",rows=rows)

@app.route("/admin/anggota", methods=["GET","POST"])
@permission_required("members")
def members():
    if request.method=="POST":
        item_id=request.form.get("item_id"); status=request.form.get("status","baru")
        if status not in ("baru","dihubungi","diterima","ditolak"): abort(400)
        db().execute("UPDATE members SET status=? WHERE id=?",(status,item_id)); db().commit()
        flash("Status anggota diperbarui.","success"); return redirect(url_for("members"))
    rows=db().execute("SELECT * FROM members ORDER BY id DESC").fetchall()
    return render_template("list.html",page="members",title="Manajemen Anggota",rows=rows)

@app.route("/admin/admin", methods=["GET","POST"])
@permission_required("admins")
def admins():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
        password=request.form.get("password",""); role=request.form.get("role","")
        if not name or "@" not in email or len(password)<12 or role not in ROLES or role=="owner":
            flash("Isi data dengan benar. Kata sandi minimal 12 karakter; role owner hanya dapat dimiliki pemilik utama.","error")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",(name,email,generate_password_hash(password),role)); db().commit()
                flash("Akun admin berhasil dibuat.","success")
            except sqlite3.IntegrityError: flash("Email tersebut sudah digunakan.","error")
        return redirect(url_for("admins"))
    rows=db().execute("SELECT id,name,email,role,active,created_at FROM users ORDER BY id").fetchall()
    return render_template("list.html",page="admins",title="Tim & Akun Admin",rows=rows)

@app.route("/admin/admin/<int:item_id>/toggle", methods=["POST"])
@permission_required("admins")
def toggle_admin(item_id):
    if item_id==session["user_id"]: flash("Anda tidak dapat menonaktifkan akun sendiri.","error")
    else:
        db().execute("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=? AND role!='owner'",(item_id,)); db().commit()
        flash("Status akun diperbarui.","success")
    return redirect(url_for("admins"))

@app.errorhandler(403)
def forbidden(_): return render_template("message.html",title="Akses ditolak",message="Akun Anda tidak memiliki izin untuk membuka halaman ini."),403
@app.errorhandler(400)
def bad_request(e): return render_template("message.html",title="Permintaan tidak valid",message=getattr(e,"description","Silakan muat ulang halaman.")),400

if __name__=="__main__":
    init_db()
    print("Database siap. Jalankan: flask --app app run")
