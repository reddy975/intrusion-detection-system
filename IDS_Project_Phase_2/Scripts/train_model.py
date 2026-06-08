import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# --- CONFIG ---
DATA_PATH = "models/preprocessed_data.pkl"
MODEL_SAVE_PATH = "models/rf_model.pkl"

# --- LOAD PREPROCESSED DATA ---
print("[INFO] Loading preprocessed dataset...")
data = joblib.load(DATA_PATH)

X_train = data['X_train']
X_test = data['X_test']
y_train = data['y_train']
y_test = data['y_test']

# --- TRAIN RANDOM FOREST MODEL ---
print("[INFO] Training Random Forest classifier...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# --- EVALUATE MODEL ---
print("[INFO] Evaluating model...")
y_pred = clf.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, digits=4)
conf_matrix = confusion_matrix(y_test, y_pred)

print(f"\n✅ Accuracy: {accuracy:.4f}")
print(f"\n📊 Classification Report:\n{report}")
print(f"\n🧾 Confusion Matrix:\n{conf_matrix}")

# --- SAVE TRAINED MODEL ---
joblib.dump(clf, MODEL_SAVE_PATH)
print(f"\n[✅ SUCCESS] Trained model saved to → {MODEL_SAVE_PATH}")
