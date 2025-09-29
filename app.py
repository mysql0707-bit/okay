# app.py
import os
import ipaddress
from datetime import datetime
from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor, Json

app = Flask(__name__)
DB_DSN = os.environ.get("DB_DSN")  # e.g. postgresql://user:pass@host:5432/db

def get_conn():
    return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS observed_endpoints (
        id BIGSERIAL PRIMARY KEY,
        ip INET NOT NULL UNIQUE,
        family SMALLINT NOT NULL,
        device_id TEXT,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        sensor TEXT,
        public BOOLEAN DEFAULT FALSE,
        user_agent TEXT,
        raw_payload JSONB
    );
    """)
    conn.commit()
    cur.close()
    conn.close()

@app.before_first_request
def setup():
    init_db()

@app.route("/api/v1/report", methods=["POST"])
def report():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid json"}), 400

    local_ips = data.get("local_ips", [])
    public_ipv4 = data.get("public_ipv4")
    public_ipv6 = data.get("public_ipv6")
    ua = request.headers.get("User-Agent", "")

    # device_id = ưu tiên public IP, nếu không thì lấy local IP đầu tiên
    device_id = public_ipv4 or public_ipv6 or (local_ips[0] if local_ips else "unknown")

    now = datetime.utcnow()
    conn = get_conn()
    cur = conn.cursor()

    def upsert(ip, is_public=False):
        if not ip or not validate_ip(ip):
            return
        family = 4 if ":" not in ip else 6
        cur.execute("""
        INSERT INTO observed_endpoints (ip, family, device_id, first_seen, last_seen, sensor, public, user_agent, raw_payload)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (ip) DO UPDATE
          SET last_seen = EXCLUDED.last_seen,
              device_id = EXCLUDED.device_id,
              public = EXCLUDED.public OR observed_endpoints.public,
              user_agent = EXCLUDED.user_agent,
              raw_payload = EXCLUDED.raw_payload
        """, (
            ip, family, device_id, now, now, device_id, is_public, ua, Json(data)
        ))

    for ip in local_ips:
        upsert(ip, False)
    if public_ipv4:
        upsert(public_ipv4, True)
    if public_ipv6:
        upsert(public_ipv6, True)

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "ok", "device_id": device_id}), 200

@app.route("/api/v1/logs", methods=["GET"])
def logs():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, ip::text as ip, device_id, public, last_seen FROM observed_endpoints ORDER BY last_seen DESC LIMIT 50")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
