import os
import joblib
import pandas as pd

from backend.risk_engine import calculate_risk, risk_level

MODEL_PATH = "model/ai_ids_model.pkl"
PROTOCOL_ENCODER_PATH = "model/protocol_encoder.pkl"
LABEL_ENCODER_PATH = "model/label_encoder.pkl"

model = None
protocol_encoder = None
label_encoder = None

if (
    os.path.exists(MODEL_PATH)
    and os.path.exists(PROTOCOL_ENCODER_PATH)
    and os.path.exists(LABEL_ENCODER_PATH)
):
    model = joblib.load(MODEL_PATH)
    protocol_encoder = joblib.load(PROTOCOL_ENCODER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)


def rule_based_detection(row):
    packet_count = int(row.get("packet_count", 0))
    failed_logins = int(row.get("failed_logins", 0))
    port_scan_count = int(row.get("port_scan_count", 0))
    request_rate = int(row.get("request_rate", 0))

    if failed_logins >= 8:
        return "Brute Force", 88.0

    if request_rate >= 500 or packet_count >= 2400:
        return "DDoS", 92.0

    if port_scan_count >= 15:
        return "Port Scan", 85.0

    if request_rate >= 180:
        return "Web Attack", 81.0

    return "Normal", 96.0


def ai_detection(row):
    protocol = str(row.get("protocol", "TCP"))

    if protocol_encoder is None or label_encoder is None or model is None:
        return rule_based_detection(row)

    if protocol not in protocol_encoder.classes_:
        protocol = "TCP"

    protocol_encoded = protocol_encoder.transform([protocol])[0]

    features = pd.DataFrame([{
        "packet_count": int(row.get("packet_count", 0)),
        "byte_count": int(row.get("byte_count", 0)),
        "failed_logins": int(row.get("failed_logins", 0)),
        "port_scan_count": int(row.get("port_scan_count", 0)),
        "request_rate": int(row.get("request_rate", 0)),
        "protocol_encoded": protocol_encoded
    }])

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    attack = label_encoder.inverse_transform([prediction])[0]
    confidence = round(max(probabilities) * 100, 2)

    return attack, confidence


def detect_attack(row):
    if model is not None:
        attack, confidence = ai_detection(row)
        engine = "AI Model"
    else:
        attack, confidence = rule_based_detection(row)
        engine = "Rule Engine"

    score = calculate_risk(row)

    return {
        "timestamp": row.get("timestamp", "LIVE"),
        "source_ip": row.get("source_ip", "Unknown"),
        "destination_ip": row.get("destination_ip", "Unknown"),
        "protocol": row.get("protocol", "Unknown"),
        "packet_count": int(row.get("packet_count", 0)),
        "byte_count": int(row.get("byte_count", 0)),
        "failed_logins": int(row.get("failed_logins", 0)),
        "port_scan_count": int(row.get("port_scan_count", 0)),
        "request_rate": int(row.get("request_rate", 0)),
        "attack_type": attack,
        "confidence": confidence,
        "risk_score": score,
        "risk_level": risk_level(score),
        "status": "Malicious" if attack != "Normal" else "Safe",
        "engine": engine
    }


def analyze_dataframe(df):
    required_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "packet_count",
        "byte_count",
        "failed_logins",
        "port_scan_count",
        "request_rate"
    ]

    for column in required_columns:
        if column not in df.columns:
            df[column] = "LIVE" if column == "timestamp" else 0

    results = []

    for _, row in df.iterrows():
        results.append(detect_attack(row))

    return results