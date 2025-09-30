from flask import Flask, request, jsonify, Response
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import base64

app = Flask(__name__)

# Lấy thông tin DB từ biến môi trường của Render
DB_DSN = os.getenv("DATABASE_URL")

# Tài khoản xem log (đặt trong Environment Variables trên Render)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "secret")

# Hàm kết nối PostgreSQL
def get_db_conn():
    return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)

# Khởi tạo bảng
def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_reports (
            id SERIAL PRIMARY KEY,
            device_id TEXT,
            ipv4 TEXT,
            ipv6 TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

with app.app_context():
    init_db()

# Hàm kiểm tra Basic Auth
def check_auth(auth_header):
    if not auth_header:
        return False
    try:
        scheme, b64 = auth_header.split()
        if scheme.lower() != "basic":
            return False
        decoded = base64.b64decode(b64).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username == ADMIN_USER and password == ADMIN_PASS
    except Exception:
        return False

def require_auth():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

@app.route("/")
def index():
    return "Server thu thập IP đang chạy!"

@app.route("/report", methods=["GET"])
def report():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ipv4, ipv6 = (ip, None) if ":" not in ip else (None, ip)
    device_id = ipv4 if ipv4 else ipv6

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO ip_reports (device_id, ipv4, ipv6, user_agent) VALUES (%s, %s, %s, %s)",
        (device_id, ipv4, ipv6, request.headers.get("User-Agent", "")),
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "ok", "device_id": device_id, "ipv4": ipv4, "ipv6": ipv6})

@app.route("/list", methods=["GET"])
def list_logs():
    auth = request.headers.get("Authorization")
    if not check_auth(auth):
        return require_auth()

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip_reports ORDER BY created_at DESC LIMIT 100;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)

@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    auth = request.headers.get("Authorization")
    if not check_auth(auth):
        return require_auth()

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("TRUNCATE ip_reports;")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "cleared"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
