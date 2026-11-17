import os
from werkzeug.security import generate_password_hash
from app import init_db, DB_PATH
import sqlite3
name=os.environ.get("RUANG_OWNER_NAME","").strip()
email=os.environ.get("RUANG_OWNER_EMAIL","").strip().lower()
password=os.environ.get("RUANG_OWNER_PASSWORD","")
if not name or "@" not in email or len(password)<16:
    raise SystemExit("Isi RUANG_OWNER_NAME, RUANG_OWNER_EMAIL dan RUANG_OWNER_PASSWORD (min. 16 karakter) terlebih dahulu.")
init_db()
conn=sqlite3.connect(DB_PATH)
exists=conn.execute("SELECT id FROM users WHERE role='owner'").fetchone()
if exists:
    raise SystemExit("Akun Owner sudah ada. Demi keamanan, bootstrap tidak mengubah akun yang ada.")
conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'owner')",(name,email,generate_password_hash(password)))
conn.commit(); conn.close()
print("Akun Owner berhasil dibuat. Simpan kredensial dengan aman dan segera login.")
