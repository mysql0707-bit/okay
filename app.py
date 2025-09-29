from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Bộ nhớ tạm để lưu thông tin IP
devices = []

@app.route("/")
def index():
    return "Server thu thập IP đang chạy!"

@app.route("/report", methods=["GET"])
def report():
    # Lấy IP thật của client
    if request.headers.getlist("X-Forwarded-For"):
        ip_addr = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip_addr = request.remote_addr

    record = {
        "device_id": ip_addr,  # dùng IP làm DEVICE_ID
        "ip": ip_addr,
        "time": datetime.utcnow().isoformat()
    }
    devices.append(record)

    return jsonify({"status": "ok", "recorded": record})

@app.route("/list", methods=["GET"])
def list_devices():
    return jsonify(devices)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
