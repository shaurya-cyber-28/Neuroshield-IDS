import random
import time

ACTIVE_ATTACKERS = [
    {"ip": "203.45.22.10", "type": "Brute Force Attempt"},
    {"ip": "89.12.45.200", "type": "Port Scan Activity"},
    {"ip": "172.67.44.90", "type": "Malware Indicator"},
    {"ip": "10.10.10.5", "type": "Privilege Escalation Attempt"},
    {"ip": "185.99.12.3", "type": "Suspicious Access"},
]

TEMPLATES = {
    "Brute Force Attempt": [
        "{ip} failed login for admin",
        "{ip} authentication failed for root",
        "{ip} invalid password attempt",
    ],
    "Port Scan Activity": [
        "{ip} nmap scan detected",
        "{ip} syn scan on port 22",
        "{ip} port scan detected on server",
    ],
    "Privilege Escalation Attempt": [
        "{ip} sudo privilege escalation attempt",
        "{ip} root access requested",
        "{ip} unauthorized sudo command detected",
    ],
    "Malware Indicator": [
        "{ip} malware payload detected",
        "{ip} trojan file blocked",
        "{ip} ransomware signature found",
    ],
    "Suspicious Access": [
        "{ip} unauthorized access denied",
        "{ip} firewall blocked connection",
        "{ip} suspicious blocked request",
    ],
    "Normal Activity": [
        "{ip} successful login for user",
        "{ip} normal user logout",
        "{ip} backup completed successfully",
    ]
}


def generate_batch(count=12):
    logs = []

    attacker = random.choice(ACTIVE_ATTACKERS)
    attack_ip = attacker["ip"]
    attack_type = attacker["type"]

    for _ in range(random.randint(4, 7)):
        logs.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "raw_log": random.choice(TEMPLATES[attack_type]).format(ip=attack_ip)
        })

    for _ in range(count - len(logs)):
        normal_ip = f"192.168.1.{random.randint(10, 80)}"
        logs.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "raw_log": random.choice(TEMPLATES["Normal Activity"]).format(ip=normal_ip)
        })

    random.shuffle(logs)
    return logs
