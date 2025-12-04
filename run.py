from waitress import serve
from app import app  # Impor aplikasi Flask Anda dari app.py
from app import db  # Impor aplikasi Flask Anda dari app.py
import os

with app.app_context():
    db.create_all()

# Dapatkan port dari environment variable, default ke 8000 jika tidak ada
port = int(os.environ.get('PORT', 8000))

if __name__ == '__main__':
    print(f"Starting production server. Access it at http://localhost:{port} or http://127.0.0.1:{port}")
    serve(app, host='0.0.0.0', port=port)