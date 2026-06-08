from flask_mail import Mail, Message
from flask import Flask

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anamika.rrce@gmail.com'  # your email
app.config['MAIL_PASSWORD'] = 'qkly vujy gnmp jjat'     # your Gmail app password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app)

def send_alert_email(ip, timestamp):
    try:
        with app.app_context():
            msg = Message("🚨 Alert: IP Blocked by Smart IDS",
                          recipients=["anamika.rrce@gmail.com"])
            msg.body = f"Suspicious IP blocked:\n\nIP Address: {ip}\nTimestamp: {timestamp}\nReview your logs."
            mail.send(msg)
            print(f"[✅ EMAIL SENT] Alert sent for {ip}")
    except Exception as e:
        print(f"[❌ EMAIL ERROR] {e}")
