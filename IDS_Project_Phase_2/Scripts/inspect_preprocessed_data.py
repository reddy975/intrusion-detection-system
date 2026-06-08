import joblib
import pandas as pd
import os

# --- CONFIG ---
PKL_PATH = os.path.join("models", "preprocessed_data.pkl")

# --- Load and Inspect ---
print("[INFO] Loading preprocessed data...")
data = joblib.load(PKL_PATH)

# --- Keys in the dictionary ---
print("\n🔑 Keys found in preprocessed_data.pkl:")
for key in data.keys():
    print(f"  - {key}")

# --- Scaler Info ---
scaler = data.get('scaler', None)
if scaler:
    print(f"\n📏 Scaler type: {type(scaler).__name__}")
    print(f"Scaler details: {scaler}")
else:
    print("❌ Scaler not found in the file.")

# --- Feature Names ---
features = data.get('feature_names', [])
print(f"\n📊 Feature Names ({len(features)} total):")
for i, name in enumerate(features, start=1):
    print(f"{i}. {name}")

# --- Simulate and transform dummy row ---
if scaler and features:
    dummy_row = pd.DataFrame([[0] * len(features)], columns=features)
    scaled_row = scaler.transform(dummy_row)
    print("\n🧪 Transformed Dummy Row:")
    print(scaled_row)
else:
    print("\n⚠️ Cannot perform transformation — missing scaler or feature names.")
