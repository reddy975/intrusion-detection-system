import pandas as pd
import joblib
import os
import sys
import numpy as np
from datetime import datetime

# Add app directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app')))
from email_utils import send_alert_email

# --- CONFIG ---
MODEL_PATH = "models/rf_model.pkl"
SCALER_PATH = "models/preprocessed_data.pkl"
BLOCK_LOG_PATH = "Log/blocked_ips.csv"
source_ip = "192.168.1.91"

# --- Load model and preprocessed data ---
print("[INFO] Loading trained model and scaler...")
model = joblib.load(MODEL_PATH)
preproc_data = joblib.load(SCALER_PATH)

scaler = preproc_data['scaler']
feature_names = preproc_data['feature_names']
X_test = preproc_data['X_test']
y_test = preproc_data['y_test']

# --- Find a real NORMAL flow sample ---
print("[INFO] Searching for a real 'Normal' flow in test set...")
normal_flow_scaled = None
for i, label in enumerate(y_test):
    if label == 1:  # 1 = Normal (assuming your encoding)
        normal_flow_scaled = X_test[i].reshape(1, -1)
        break

if normal_flow_scaled is None:
    print("[ERROR] No normal sample found in test data.")
    sys.exit(1)

# --- Predict using real normal sample ---
prediction = model.predict(normal_flow_scaled)[0]
proba = model.predict_proba(normal_flow_scaled)[0]

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if prediction == 1:
    status = 'Normal'
    print(f"[SAFE] Traffic from {source_ip} classified as Normal")
else:
    status = 'Blocked (Simulated)'
    print(f"[🚨 ALERT] Traffic from {source_ip} classified as Attack!")
    send_alert_email(source_ip, timestamp)

# --- Optional: show original unscaled feature values ---
original_features = scaler.inverse_transform(normal_flow_scaled)[0]
print("\n[DEBUG] Original (Unscaled) Feature Values:")
for fname, val in zip(feature_names, original_features):
    print(f"{fname}: {val}")

# --- Log only if attack detected ---
if prediction == 0:
    os.makedirs("Log", exist_ok=True)
    log_entry = {'timestamp': timestamp, 'src_ip': source_ip, 'status': status}

    if os.path.exists(BLOCK_LOG_PATH):
        log_df = pd.read_csv(BLOCK_LOG_PATH)
        log_df = pd.concat([log_df, pd.DataFrame([log_entry])], ignore_index=True)
    else:
        log_df = pd.DataFrame([log_entry])

    log_df.to_csv(BLOCK_LOG_PATH, index=False)
    print(f"\n[LOGGED] IP {source_ip} written to log with status: {status}")
