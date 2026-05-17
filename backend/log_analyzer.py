import re
from collections import defaultdict, Counter


MITRE_MAP = {
    "DDoS Attack": {
        "technique": "T1498",
        "name": "Network Denial of Service",
        "stage": "Impact",
        "reason": "Flooding or abnormal request-volume indicators suggest denial-of-service behavior."
    },
    "Brute Force Attempt": {
        "technique": "T1110",
        "name": "Brute Force",
        "stage": "Credential Access",
        "reason": "Repeated failed authentication attempts indicate possible password guessing."
    },
    "Port Scan Activity": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "stage": "Discovery",
        "reason": "Scanning activity suggests reconnaissance against exposed services."
    },
    "Privilege Escalation Attempt": {
        "technique": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "stage": "Privilege Escalation",
        "reason": "Root or sudo-related activity suggests an attempt to gain elevated permissions."
    },
    "Malware Indicator": {
        "technique": "T1204",
        "name": "User Execution / Malicious File",
        "stage": "Execution",
        "reason": "Malware, payload, trojan, or ransomware indicators were found in the logs."
    },
    "Suspicious Access": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "stage": "Initial Access",
        "reason": "Unauthorized, blocked, or denied access attempts suggest suspicious account activity."
    },
    "SQL Injection Attack": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "reason": "SQL injection patterns suggest an attempt to exploit application input handling."
    },
    "XSS Attack": {
        "technique": "T1189",
        "name": "Drive-by Compromise",
        "stage": "Initial Access",
        "reason": "Script injection patterns suggest cross-site scripting activity."
    },
    "Command Injection": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "stage": "Execution",
        "reason": "Command execution patterns indicate possible shell or interpreter abuse."
    },
    "Directory Traversal Attack": {
        "technique": "T1083",
        "name": "File and Directory Discovery",
        "stage": "Discovery",
        "reason": "Traversal strings suggest attempts to access restricted filesystem paths."
    },
    "Phishing Attempt": {
        "technique": "T1566",
        "name": "Phishing",
        "stage": "Initial Access",
        "reason": "Credential-harvesting or fake-login indicators suggest phishing activity."
    },
    "DNS Tunneling": {
        "technique": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "stage": "Command and Control",
        "reason": "Suspicious DNS activity suggests possible tunneling or data movement through DNS."
    },
    "Botnet Activity": {
        "technique": "T1071",
        "name": "Application Layer Protocol",
        "stage": "Command and Control",
        "reason": "C2 or botnet indicators suggest communication with attacker-controlled infrastructure."
    },
    "Data Exfiltration": {
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "stage": "Exfiltration",
        "reason": "Large outbound transfers or sensitive file movement suggest data theft."
    },
    "Normal Activity": {
        "technique": "N/A",
        "name": "Normal System Activity",
        "stage": "Benign",
        "reason": "The log matches expected operational behavior."
    }
}


KILL_CHAIN_ORDER = [
    "Discovery",
    "Initial Access",
    "Credential Access",
    "Execution",
    "Privilege Escalation",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


def extract_ip(line):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    return match.group(0) if match else "Unknown"


def classify_log(line):
    text = line.lower()

    if any(w in text for w in [
        "data exfiltration", "data exfil", "data leak", "large outbound transfer",
        "unauthorized data transfer", "sensitive files uploaded",
        "confidential data sent", "bulk download detected",
        "unusual outbound traffic", "files copied to external server"
    ]):
        return "Data Exfiltration", 98.0

    if any(w in text for w in [
        "ddos", "dos attack", "high request rate", "packet flood",
        "udp flood", "http flood", "too many requests", "traffic flood"
    ]):
        return "DDoS Attack", 98.0

    if any(w in text for w in [
        "failed login", "authentication failed", "invalid password",
        "multiple login attempts", "login failure"
    ]):
        return "Brute Force Attempt", 95.0

    if any(w in text for w in [
        "nmap", "syn scan", "port scan", "ports scanned"
    ]):
        return "Port Scan Activity", 94.0

    if any(w in text for w in [
        "sudo", "root access", "privilege escalation",
        "unauthorized sudo", "admin rights escalation"
    ]):
        return "Privilege Escalation Attempt", 96.0

    if any(w in text for w in [
        "malware", "trojan", "ransomware", "payload",
        "virus detected"
    ]):
        return "Malware Indicator", 97.0

    if any(w in text for w in [
        "unauthorized access", "access denied",
        "firewall blocked", "policy violation", "blocked request"
    ]):
        return "Suspicious Access", 90.0

    if any(w in text for w in [
        "select * from", "union select", "or 1=1",
        "sql injection", "database error"
    ]):
        return "SQL Injection Attack", 97.0

    if any(w in text for w in [
        "<script>", "javascript:", "xss attempt",
        "cross-site scripting"
    ]):
        return "XSS Attack", 95.0

    if any(w in text for w in [
        "cmd=", "bash -c", "exec(", "shell execution",
        "command injection"
    ]):
        return "Command Injection", 96.0

    if any(w in text for w in [
        "../", "..\\", "/etc/passwd", "directory traversal"
    ]):
        return "Directory Traversal Attack", 96.0

    if any(w in text for w in [
        "phishing", "fake login page", "credential harvest"
    ]):
        return "Phishing Attempt", 90.0

    if any(w in text for w in [
        "dns query", "suspicious dns", "tunnel detected",
        "dns exfiltration"
    ]):
        return "DNS Tunneling", 92.0

    if any(w in text for w in [
        "botnet", "command and control", "c2 server",
        "infected host"
    ]):
        return "Botnet Activity", 94.0

    if any(w in text for w in [
        "successful login", "backup completed",
        "service started", "normal activity",
        "normal user logout", "health check passed"
    ]):
        return "Normal Activity", 92.0

    return "Normal Activity", 85.0


def risk_score(threat, count):
    base = {
        "Normal Activity": 5,
        "Suspicious Access": 55,
        "Port Scan Activity": 68,
        "Brute Force Attempt": 72,
        "DDoS Attack": 90,
        "Privilege Escalation Attempt": 88,
        "Malware Indicator": 95,
        "SQL Injection Attack": 92,
        "XSS Attack": 85,
        "Command Injection": 93,
        "Directory Traversal Attack": 90,
        "Phishing Attempt": 80,
        "DNS Tunneling": 88,
        "Botnet Activity": 92,
        "Data Exfiltration": 96
    }

    if threat == "Normal Activity":
        return 5

    return min(base.get(threat, 30) + min(count * 4, 15), 100)


def risk_level(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def recommendation(threat):
    return {
        "DDoS Attack": "Enable rate limiting, block attacking IPs, review WAF/CDN logs, and monitor bandwidth spikes.",
        "Brute Force Attempt": "Enable MFA, lock targeted accounts, reset credentials, and block repeated authentication sources.",
        "Port Scan Activity": "Close unused ports, harden firewall rules, and monitor the scanning source for follow-up attacks.",
        "Privilege Escalation Attempt": "Audit sudo/root access, review command history, and validate account permissions.",
        "Malware Indicator": "Isolate the affected host, scan for malware, collect IOC evidence, and inspect lateral movement.",
        "Suspicious Access": "Verify user behavior, inspect firewall/security logs, and validate whether access was authorized.",
        "SQL Injection Attack": "Sanitize input, use prepared statements, patch vulnerable endpoints, and inspect database logs.",
        "XSS Attack": "Escape user input, apply CSP headers, sanitize frontend output, and review affected pages.",
        "Command Injection": "Validate input, restrict shell execution, review vulnerable parameters, and patch backend code.",
        "Directory Traversal Attack": "Sanitize file paths, restrict file permissions, and block traversal patterns at the WAF.",
        "Phishing Attempt": "Block phishing URLs, warn users, inspect credential exposure, and reset compromised accounts.",
        "DNS Tunneling": "Monitor DNS traffic, block suspicious domains, inspect exfiltration attempts, and review DNS logs.",
        "Botnet Activity": "Block C2 traffic, isolate infected hosts, inspect persistence mechanisms, and collect network IOCs.",
        "Data Exfiltration": "Block outbound connection, isolate host, review transferred files, and investigate compromised credentials.",
        "Normal Activity": "No action required. Continue monitoring."
    }.get(threat, "Investigate manually.")


def build_attack_chain(results):
    stages_seen = {}

    for result in results:
        stage = result["mitre_stage"]
        if stage != "Benign":
            stages_seen[stage] = {
                "stage": stage,
                "threat": result["threat"],
                "ip": result["ip"],
                "risk_score": result["risk_score"],
                "technique": result["mitre_technique"],
                "name": result["mitre_name"]
            }

    chain = []
    for stage in KILL_CHAIN_ORDER:
        if stage in stages_seen:
            chain.append(stages_seen[stage])

    is_multistage = len(chain) >= 3
    chain_score = min(sum(item["risk_score"] for item in chain) // max(len(chain), 1) + len(chain) * 5, 100) if chain else 0

    return {
        "detected": is_multistage,
        "stages": chain,
        "stage_count": len(chain),
        "chain_score": chain_score,
        "summary": "Multi-stage attack chain detected." if is_multistage else "No complete multi-stage attack chain detected."
    }


def build_ai_summary(results, attack_chain):
    threats = [r for r in results if r["threat"] != "Normal Activity"]

    if not threats:
        return "No suspicious activity was identified. The analyzed logs appear to represent normal system behavior."

    top = max(threats, key=lambda x: x["risk_score"])
    text = (
        f"The most severe incident is {top['threat']} from {top['ip']} "
        f"with a risk score of {top['risk_score']} and confidence of {top['confidence']}%. "
        f"This maps to MITRE ATT&CK {top['mitre_technique']} ({top['mitre_name']}) "
        f"in the {top['mitre_stage']} stage. "
    )

    if attack_chain["detected"]:
        text += (
            f"A multi-stage attack chain was detected across {attack_chain['stage_count']} stages, "
            f"indicating coordinated attacker progression rather than isolated alerts."
        )
    else:
        text += "The events appear to be isolated or limited-stage alerts based on the current log batch."

    return text


def analyze_logs(log_input):
    if isinstance(log_input, str):
        lines = [line.strip() for line in log_input.splitlines() if line.strip()]
    else:
        lines = [item.get("raw_log", "").strip() for item in log_input if item.get("raw_log")]

    grouped = defaultdict(list)

    for line in lines:
        ip = extract_ip(line)
        threat, confidence = classify_log(line)
        grouped[(ip, threat)].append({
            "raw_log": line,
            "confidence": confidence
        })

    results = []
    ip_counter = Counter()
    threat_counter = Counter()
    stage_counter = Counter()

    for (ip, threat), events in grouped.items():
        count = len(events)
        avg_conf = round(sum(e["confidence"] for e in events) / count, 2)
        score = risk_score(threat, count)
        mitre = MITRE_MAP.get(threat, MITRE_MAP["Normal Activity"])

        ip_counter[ip] += count
        threat_counter[threat] += count
        stage_counter[mitre["stage"]] += count

        results.append({
            "ip": ip,
            "threat": threat,
            "risk_score": score,
            "risk_level": risk_level(score),
            "confidence": avg_conf,
            "engine": "Hybrid AI + MITRE Detection Engine",
            "occurrences": count,
            "raw_log": events[0]["raw_log"],
            "raw_logs": [e["raw_log"] for e in events],
            "recommendation": recommendation(threat),
            "mitre_technique": mitre["technique"],
            "mitre_name": mitre["name"],
            "mitre_stage": mitre["stage"],
            "ai_reason": mitre["reason"]
        })

    results = sorted(results, key=lambda x: x["risk_score"], reverse=True)

    threats = [r for r in results if r["threat"] != "Normal Activity"]
    critical = [r for r in results if r["risk_level"] == "CRITICAL"]

    top_attacker = "None"
    if threats:
        top_attacker = Counter({r["ip"]: r["occurrences"] for r in threats}).most_common(1)[0][0]

    profiles = []

    for ip, total in ip_counter.items():
        ip_results = [r for r in results if r["ip"] == ip]
        max_risk_item = max(ip_results, key=lambda x: x["risk_score"])

        profiles.append({
            "ip": ip,
            "events": total,
            "main_threat": max_risk_item["threat"],
            "max_risk": max_risk_item["risk_score"],
            "status": "Blocked" if max_risk_item["risk_score"] >= 85 else "Watching"
        })

    profiles = sorted(profiles, key=lambda x: x["max_risk"], reverse=True)

    attack_chain = build_attack_chain(results)
    ai_summary = build_ai_summary(results, attack_chain)

    summary = {
        "total": sum(ip_counter.values()),
        "threats": sum(r["occurrences"] for r in threats),
        "critical": len(critical),
        "unique_ips": len(ip_counter),
        "top_attacker": top_attacker,
        "labels": list(threat_counter.keys()),
        "values": list(threat_counter.values()),
        "stages": list(stage_counter.keys()),
        "stage_values": list(stage_counter.values()),
        "profiles": profiles,
        "attack_chain": attack_chain,
        "ai_summary": ai_summary
    }

    return results, summary