# dashboard.py
import os
import json
import queue
from collections import deque
from datetime import datetime
import sqlite3

from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, Response, session
)
import joblib
import pandas as pd
import smtplib
from email.mime.text import MIMEText

# -------------------- Flask setup --------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# -------------------- Model & Scaler --------------------
MODEL_PATH = os.path.join("models", "rf_model.pkl")
SCALER_PATH = os.path.join("models", "preprocessed_data.pkl")

print("[INFO] Loading model and scaler...")
preproc_data = joblib.load(SCALER_PATH)
scaler = preproc_data['scaler']
feature_names = preproc_data['feature_names']
model = joblib.load(MODEL_PATH)

# -------------------- Database setup --------------------
DB_FILE = "ids_logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        status TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

def log_ip(ip, status):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO blocked_ips (timestamp, src_ip, status) VALUES (?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, status))
    conn.commit()
    conn.close()

def unblock_ip_from_db(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips WHERE src_ip=?", (ip,))
    conn.commit()
    conn.close()

def get_blocked_ips():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, src_ip, status FROM blocked_ips ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"timestamp": r[0], "src_ip": r[1], "status": r[2]} for r in rows]

# -------------------- Email Alert (optional) --------------------
ADMIN_EMAIL = "anamika.rrce@gmail.com"  # change
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "anamika.rrce@gmail.com"  # change
EMAIL_PASS = "qkly vujy gnmp jjat"         # change

def send_alert_email(ip, timestamp):
    try:
        subject = "Smart IDS Alert - Suspicious Activity"
        body = f"Intrusion detected from IP {ip} at {timestamp}. The IP has been blocked.Review you Network"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = ADMIN_EMAIL

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, ADMIN_EMAIL, msg.as_string())
        server.quit()
        print(f"[INFO] Email alert sent to {ADMIN_EMAIL}")
    except Exception as e:
        print(f"[ERROR] Email sending failed: {e}")

# -------------------- In-memory SSE queue & history --------------------
alert_queue = queue.Queue()            # used by SSE stream
alerts_history = deque(maxlen=200)     # recent alerts (for initial page load)

# -------------------- Routes --------------------
@app.route("/", methods=['GET'])
def home():
    if not session.get('logged_in'):
        return render_template("dashboard.html", session=session, menu='login')

    ips = get_blocked_ips()
    total_logs = len(ips)
    blocked = len([r for r in ips if "Blocked" in r["status"]])
    safe = total_logs - blocked
    unique_ips = len(set([r["src_ip"] for r in ips]))

    # optionally draw a small chart (dashboard.html expects chart_url variable)
    chart_url = None
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import base64
        from io import BytesIO
        df = pd.DataFrame(ips)
        if not df.empty:
            top_ips = df["src_ip"].value_counts().head(5)
            fig, ax = plt.subplots()
            top_ips.plot(kind="bar", ax=ax, color="tomato")
            ax.set_title("Top Blocked IPs")
            ax.set_ylabel("Count")
            buf = BytesIO()
            plt.savefig(buf, format="png", bbox_inches="tight")
            buf.seek(0)
            chart_url = base64.b64encode(buf.getvalue()).decode("utf-8")
            plt.close(fig)
    except Exception:
        chart_url = None

    return render_template(
        "dashboard.html",
        menu="home",
        total_count=total_logs,
        block_count=blocked,
        safe_count=safe,
        unique_ips=unique_ips,
        chart_url=chart_url,
        session=session
    )

@app.route("/predict", methods=['GET'])
def predict():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    # Predict page will obtain historical alerts via AJAX and then listen to SSE
    return render_template("dashboard.html", menu="predict", feature_names=feature_names, session=session)

@app.route("/blocked_ips")
def blocked_ips():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template("dashboard.html", menu="blocked_ips", blocked_ips=get_blocked_ips(), session=session)

@app.route("/unblock/<ip>", methods=['POST'])
def unblock_ip(ip):
    unblock_ip_from_db(ip)
    return redirect(url_for("blocked_ips"))

# -------------------- API: receive flow JSON from Kali --------------------
@app.route("/api/flow", methods=["POST"])
def api_flow():
    """
    Expects JSON from sniffer with keys matching feature_names plus 'src_ip' and optionally 'dst_ip'.
    Example:
    {
      "src_ip": "192.168.119.227",
      "dst_ip": "8.8.8.8",
      "pkSeqID": 42.05,
      "stime": 82.25,
      ...
    }
    """
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status":"error", "error":"no json"}), 400

        # Make sure we have src_ip for logging
        src_ip = data.get("src_ip", "0.0.0.0")

        # Build feature vector in the correct order (missing features default to 0.0)
        flow_values = []
        features_dict = {}
        for fname in feature_names:
            val = data.get(fname, 0.0)
            try:
                num = float(val)
            except Exception:
                # if original value is non-numeric, try to coerce or default 0.0
                try:
                    num = float(str(val))
                except Exception:
                    num = 0.0
            flow_values.append(num)
            features_dict[fname] = num

        # Prepare DataFrame and scale
        df_input = pd.DataFrame([flow_values], columns=feature_names)
        scaled_input = scaler.transform(df_input)

        # Predict
        pred = model.predict(scaled_input)[0]
        proba = model.predict_proba(scaled_input)[0] if hasattr(model, "predict_proba") else [None, None]
        status = "Blocked (Real)" if int(pred) == 1 else "Normal"

        # Log to DB
        log_ip(src_ip, status)

        # Send email if required
        if int(pred) == 1:
            send_alert_email(src_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Build alert payload that front-end expects (includes features)
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": src_ip,
            "dst_ip": data.get("dst_ip", ""),
            "prediction": status,
            "proba": proba.tolist() if hasattr(proba, "tolist") else list(proba),
            "features": features_dict
        }

        # push to SSE queue and history
        alert_queue.put(alert)
        alerts_history.appendleft(alert)

        print(f"[API_FLOW] {src_ip} -> {status} (prob={alert['proba']})")
        return jsonify({"status":"ok", "alert": alert}), 200

    except Exception as e:
        print("[API_FLOW ERROR]", e)
        return jsonify({"status":"error", "error": str(e)}), 500

# -------------------- SSE: stream alerts to browser --------------------
@app.route("/stream_alerts")
def stream_alerts():
    def event_stream():
        # When client connects, first send a small welcome comment (keeps connection alive in some proxies)
        yield ": connected\n\n"
        while True:
            alert = alert_queue.get()  # blocking
            # send JSON string (clients will parse)
            payload = json.dumps(alert)
            yield f"data: {payload}\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

# -------------------- API: get recent history (on page load) --------------------
@app.route("/api/history")
def api_history():
    # returns list of recent alerts (most recent first)
    try:
        return jsonify({"status":"ok", "history": list(alerts_history)}), 200
    except Exception as e:
        return jsonify({"status":"error", "error": str(e)}), 500

# -------------------- Simple login/logout --------------------
@app.route("/login", methods=['POST'])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == "admin" and password == "admin":
        session["logged_in"] = True
        return redirect(url_for("home"))
    return render_template("dashboard.html", session=session, menu='login', error="Invalid Credentials")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# -------------------- Run --------------------
if __name__ == "__main__":
    # IMPORTANT: keep debug=False when showing to others; debug=True is helpful during development
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True)

