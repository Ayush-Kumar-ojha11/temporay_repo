# =========================
# NEW PREPROCESSING PIPELINE (10/10 UPGRADE)
# =========================
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# %matplotlib inline



# 1. LOAD DATA & CLEAN
df = pd.read_csv("sleep_mobile_stress_dataset_15000.csv")
df.drop(columns=["user_id", "sleep_quality_score", "mental_fatigue_score"], inplace=True)
from sklearn.preprocessing import LabelEncoder
df['gender'] = LabelEncoder().fit_transform(df['gender'])
df['occupation'] = LabelEncoder().fit_transform(df['occupation'])

print("Data Loaded and Categoricals Encoded. Shape:", df.shape)


# 2. ADVANCED FEATURE ENGINEERING (Non-Linear Context)
# Adding interaction terms to capture combined stressors
df["Screen_to_Sleep_Ratio"] = df["daily_screen_time_hours"] / (df["sleep_duration_hours"] + 0.001)
df["Caffeine_vs_Sleep"] = df["caffeine_intake_cups"] / (df["sleep_duration_hours"] + 0.001)

print("Engineered Non-Linear Features Added!")


# 3. FEATURE ENGINEERING & TARGET
X = df.drop(columns=["stress_level"])
y = df["stress_level"]


# 4. SPLIT DATA (50% Train, 30% Test, 20% Stratified K-Fold Pool)
y_binned = pd.qcut(y, q=5, labels=False, duplicates='drop')

X_temp, X_kfold, y_temp, y_kfold = train_test_split(
    X, y, test_size=0.20, stratify=y_binned, random_state=42
)

y_temp_binned = pd.qcut(y_temp, q=5, labels=False, duplicates='drop')
X_train, X_test, y_train, y_test = train_test_split(
    X_temp, y_temp, test_size=0.375, stratify=y_temp_binned, random_state=42
)

print(f"Training Set (50%): {len(X_train)} | Testing Set (30%): {len(X_test)}")


# 5. STANDARDIZE FEATURES
scaler = StandardScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
X_kfold_scaled = pd.DataFrame(scaler.transform(X_kfold), columns=X_kfold.columns)


# 6. EXPLORATORY GRAPHS
plt.figure(figsize=(12, 10))
corr = df.corr()
top_corr_features = corr.index[abs(corr["stress_level"]) > 0.1]
sns.heatmap(df[top_corr_features].corr(), annot=True, cmap="coolwarm", fmt=".2f")
plt.title("Correlation Heatmap (Including Engineered Features)")
# plt.show()


# 7. SAVE PROCESSED DATA TO DISK
X_train_scaled.to_csv("X_train.csv", index=False)
X_test_scaled.to_csv("X_test.csv", index=False)
X_kfold_scaled.to_csv("X_kfold.csv", index=False)

y_train.to_csv("y_train.csv", index=False)
y_test.to_csv("y_test.csv", index=False)
y_kfold.to_csv("y_kfold.csv", index=False)

print("All preprocessed data successfully exported to CSVs!")


