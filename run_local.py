from app import app, init_db
from waitress import serve
init_db()
serve(app, host="127.0.0.1", port=8000)
