from flask import Flask, request
import os
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

DB_DSN = os.environ.get("DB_DSN")

def init_db():
    conn = psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_logs (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

@app.route("/", methods=["GET", "POST"])
def collect():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "")
    conn = psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    cur.execute("INSERT INTO ip_logs (ip, user_agent) VALUES (%s, %s)", (ip, ua))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok", "ip": ip}

@app.route("/logs")
def logs():
    conn = psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip_logs ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {"logs": rows}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
