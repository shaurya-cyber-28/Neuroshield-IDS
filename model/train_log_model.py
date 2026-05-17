import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

logs = [
    "successful login for user",
    "normal user logout",
    "backup completed successfully",
    "service started successfully",
    "system update completed",
    "user session closed",
    "file uploaded successfully",
    "health check passed",

    "failed login for admin",
    "authentication failed for root",
    "invalid password attempt",
    "multiple failed ssh login attempts",

    "nmap scan detected",
    "syn scan on port 22",
    "port scan detected",
    "multiple ports scanned",

    "ddos attack detected",
    "high request rate detected",
    "traffic flood detected",
    "udp flood detected",
    "http flood attack",
    "too many requests from same ip",
    "packet flood detected",

    "sudo privilege escalation attempt",
    "root access requested",
    "unauthorized sudo command",
    "admin rights escalation attempt",

    "malware payload detected",
    "trojan file blocked",
    "ransomware signature found",
    "malicious payload execution",

    "unauthorized access denied",
    "firewall blocked connection",
    "suspicious blocked request",
    "policy violation blocked"
]

labels = [
    "Normal Activity","Normal Activity","Normal Activity","Normal Activity",
    "Normal Activity","Normal Activity","Normal Activity","Normal Activity",

    "Brute Force Attempt","Brute Force Attempt","Brute Force Attempt","Brute Force Attempt",

    "Port Scan Activity","Port Scan Activity","Port Scan Activity","Port Scan Activity",

    "DDoS Attack","DDoS Attack","DDoS Attack","DDoS Attack",
    "DDoS Attack","DDoS Attack","DDoS Attack",

    "Privilege Escalation Attempt","Privilege Escalation Attempt","Privilege Escalation Attempt","Privilege Escalation Attempt",

    "Malware Indicator","Malware Indicator","Malware Indicator","Malware Indicator",

    "Suspicious Access","Suspicious Access","Suspicious Access","Suspicious Access"
]

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("classifier", LogisticRegression(max_iter=1000))
])

model.fit(logs, labels)
joblib.dump(model, "model/log_ai_model.pkl")

print("LogShield AI model trained successfully.")