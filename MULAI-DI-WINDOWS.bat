@echo off
cd /d %~dp0
if not exist .env (
  copy .env.example .env >nul
  echo File .env telah dibuat.
  echo Buka file .env, isi nama, email, kata sandi Owner, dan secret key.
  echo Setelah disimpan, jalankan MULAI-DI-WINDOWS.bat sekali lagi.
  pause
  exit /b
)
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist ruang.db (
  python bootstrap_owner.py
  if errorlevel 1 pause & exit /b 1
) else (
  echo Database sudah ada. Akun Owner tidak dibuat ulang.
)
echo Dashboard akan tersedia di http://127.0.0.1:8000
python run_local.py
pause
