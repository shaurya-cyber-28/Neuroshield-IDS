def calculate_risk(row):
    score = 0

    score += min(int(row.get("packet_count", 0)) // 50, 25)
    score += min(int(row.get("byte_count", 0)) // 20000, 20)
    score += min(int(row.get("failed_logins", 0)) * 4, 25)
    score += min(int(row.get("port_scan_count", 0)) * 3, 20)
    score += min(int(row.get("request_rate", 0)) // 20, 10)

    return min(score, 100)


def risk_level(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"