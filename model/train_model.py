import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

df = pd.read_csv("dataset/sample_traffic.csv")

protocol_encoder = LabelEncoder()
label_encoder = LabelEncoder()

df["protocol_encoded"] = protocol_encoder.fit_transform(df["protocol"])
df["label_encoded"] = label_encoder.fit_transform(df["label"])

features = [
    "packet_count",
    "byte_count",
    "failed_logins",
    "port_scan_count",
    "request_rate",
    "protocol_encoded"
]

X = df[features]
y = df["label_encoded"]

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X, y)

predictions = model.predict(X)
accuracy = accuracy_score(y, predictions)

joblib.dump(model, "model/ai_ids_model.pkl")
joblib.dump(protocol_encoder, "model/protocol_encoder.pkl")
joblib.dump(label_encoder, "model/label_encoder.pkl")

print("AI-IDS model trained successfully.")
print(f"Training accuracy: {accuracy * 100:.2f}%")