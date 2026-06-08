import pandas as pd
import os
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from imblearn.over_sampling import SMOTE

# --- CONFIGURATION ---
DATA_FOLDER = "Dataset/ext_dataset"
FILES = [
    "reduced_data_1.csv",
    "reduced_data_2.csv",
    "reduced_data_3.csv",
    "reduced_data_4.csv"
]
OUTPUT_PATH = "models/preprocessed_data.pkl"
LABEL_COL = 'attack'  # Label column name

# --- LOAD & COMBINE FILES ---
print("[INFO] Loading and combining datasets...")
df_list = []
for file in FILES:
    file_path = os.path.join(DATA_FOLDER, file)
    df = pd.read_csv(file_path, low_memory=False)
    df_list.append(df)

df = pd.concat(df_list, ignore_index=True)
print(f"[INFO] Combined dataset shape: {df.shape}")

# --- SHOW UNIQUE LABEL VALUES ---
print("[INFO] Unique values in 'attack' column before encoding:")
print(df[LABEL_COL].unique())

if set(df[LABEL_COL].unique()).issubset({0,1}):
    print("[INFO] Labels are already numeric 0/1, skipping encoding.")
else:
    normal_labels = ['normal', 'benign', 'normal traffic']  # Adjust this list as needed
    df[LABEL_COL] = df[LABEL_COL].apply(lambda x: 0 if str(x).strip().lower() in normal_labels else 1)
    print("[INFO] Labels encoded from strings to 0/1.")

print("[INFO] Label distribution after encoding:")
print(df[LABEL_COL].value_counts())

# --- DROP COLUMNS NOT TO USE AS FEATURES ---
columns_to_drop_from_features = [
    'saddr', 'daddr', 'proto', 'sport', 'dport', 'state', 'category', 'subcategory'
]
for col in columns_to_drop_from_features:
    if col in df.columns:
        print(f"[INFO] Dropping column from features: {col}")

# --- BALANCE DATASET BY DOWNSAMPLING MAJORITY CLASS ---
count_class_0 = df[LABEL_COL].value_counts().get(0, 0)
count_class_1 = df[LABEL_COL].value_counts().get(1, 0)

if count_class_0 == 0 or count_class_1 == 0:
    raise ValueError("[ERROR] One of the classes has zero samples after encoding. Check your label encoding logic!")

if count_class_0 > count_class_1:
    df_majority = df[df[LABEL_COL] == 0]
    df_minority = df[df[LABEL_COL] == 1]
else:
    df_majority = df[df[LABEL_COL] == 1]
    df_minority = df[df[LABEL_COL] == 0]

print(f"[INFO] Majority class count: {len(df_majority)}")
print(f"[INFO] Minority class count: {len(df_minority)}")

df_majority_downsampled = df_majority.sample(n=len(df_minority), random_state=42)
df_balanced = pd.concat([df_majority_downsampled, df_minority]).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"[INFO] Balanced dataset shape: {df_balanced.shape}")
print(f"[INFO] Label distribution after balancing:")
print(df_balanced[LABEL_COL].value_counts())

# --- PREPARE FEATURES AND LABELS ---
X = df_balanced.drop(columns=columns_to_drop_from_features + [LABEL_COL], errors='ignore')
y = df_balanced[LABEL_COL]

# --- HANDLE NON-NUMERIC COLUMNS ---
non_numeric_cols = X.select_dtypes(exclude=['number']).columns.tolist()
if non_numeric_cols:
    print(f"[INFO] Non-numeric columns found in features: {non_numeric_cols}")
    for col in non_numeric_cols:
        print(f"[INFO] Converting '{col}' to numeric...")
        X[col] = pd.to_numeric(X[col], errors='coerce')
else:
    print("[INFO] No non-numeric columns found in features.")

X.fillna(0, inplace=True)

# --- APPLY SMOTE ONLY IF NEEDED ---
class_counts = y.value_counts()
if class_counts.min() / class_counts.max() < 0.9:  # 90% threshold for imbalance
    print("[INFO] Applying SMOTE to balance the dataset further...")
    sm = SMOTE(random_state=42)
    X, y = sm.fit_resample(X, y)
    print("[INFO] Label distribution after SMOTE:")
    print(pd.Series(y).value_counts())
else:
    print("[INFO] Dataset already balanced, skipping SMOTE.")

# --- SCALE FEATURES ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- SPLIT INTO TRAIN AND TEST SETS ---
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print(f"[INFO] Train set shape: {X_train.shape}, Test set shape: {X_test.shape}")

# --- SAVE THE PROCESSED DATA ---
df_processed = {
    'X_train': X_train,
    'X_test': X_test,
    'y_train': y_train,
    'y_test': y_test,
    'scaler': scaler,
    'feature_names': X.columns.tolist()
}

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
joblib.dump(df_processed, OUTPUT_PATH)
print(f"[✅ SUCCESS] Preprocessing complete. Data saved to → {OUTPUT_PATH}")