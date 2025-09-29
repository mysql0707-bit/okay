# app.py
from flask import Flask, request, jsonify
from datetime import datetime
import os
import json
import fcntl

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(APP_DIR, "ip_logs.jsonl")
MAX_BYTES = 10 * 1024 * 1024  # 10 MB rotate

app = Flask(__name__)

def rotate_if_needed():
    """Rotate DATA_FILE if size exceeds MAX_BYTES."""
    try:
        if not os.path.exists(DATA_FILE):
            return
        size = os.path.getsize(DATA_FILE)
        if size >= MAX_BYTES:
            rotated = DATA_FILE + ".1"
            # atomically move (overwrite rotated)
            try:
                os.replace(DATA_FILE, rotated)
                app.logger.info(f"Rotated {DATA_FILE} -> {rotated}")
            except Exception as e:
                app.logger.exception("Rotate failed: %s", e)
    except Exception:
        app.logger.exception("rotate_if_needed error")

def append_record(record: dict):
    """Append a JSON line to the data file with file locking."""
    rotate_if_needed()
    line = json.dumps(record, ensure_ascii=False)
    # open file and lock for write
    with open(DATA_FILE, "a+", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.write(line + "\n")
            fh.flush()
        finally:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass

def read_last_n(n=100):
    """Read last n lines from JSONL file (efficient-ish)."""
    if not os.path.exists(DATA_FILE):
        return []
    results = []
    # read backward by blocks
    with open(DATA_FILE, "rb") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            fh.seek(0, os.SEEK_END)
            filesize = fh.tell()
            block_size = 4096
            data = b""
            pos = filesize
            while pos > 0 and len(results) < n:
                read_size = block_size if pos - block_size > 0 else pos
                pos -= read_size
                fh.seek(pos)
                chunk = fh.read(read_size)
                data = chunk + data
                # split lines
                lines = data.split(b"\n")
                # keep incomplete first line for next loop
                if pos > 0:
                    data = lines[0]
                    lines = lines[1:]
                else:
                    # start of file
                    data = b""
                for ln in reversed(lines):
                    if not ln:
                        continue
                    try:
                        results.append(json.loads(ln.decode("utf-8")))
                    except Exception:
                        # skip bad lines
                        continue
            # release lock
        finally:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
    return results[:n]

@app.route("/", methods=["GET"])
def index():
    return "Server thu thập IP đang chạy!"

@app.route("/report", methods=["GET", "POST"])
def report():
    # Get client IP (respect X-Forwarded-For if present)
    xff = request.headers.getlist("X-Forwarded-For")
    if xff:
        ip_addr = xff[0].split(",")[0].strip()
    else:
        ip_addr = request.remote_addr or "unknown"

    ua = request.headers.get("User-Agent", "")
    path = request.path
    method = request.method
    ts = datetime.utcnow().isoformat() + "Z"

    record = {
        "device_id": ip_addr,   # device_id == client IP
        "ip": ip_addr,
        "user_agent": ua,
        "method": method,
        "path": path,
        "ts": ts
    }

    try:
        append_record(record)
        app.logger.info("Recorded: %s %s %s", ip_addr, method, path)
    except Exception:
        app.logger.exception("Failed to append record")

    return jsonify({"status": "ok", "record": record})

@app.route("/list", methods=["GET"])
def list_records():
    # limit param
    try:
        limit = int(request.args.get("limit", "100"))
    except Exception:
        limit = 100
    rows = read_last_n(limit)
    return jsonify({"count": len(rows), "rows": rows})

if __name__ == "__main__":
    # local debug
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
