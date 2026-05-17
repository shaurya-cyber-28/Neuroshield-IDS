import random
import time


ATTACK_PATTERNS = ["Normal", "DDoS", "Brute Force", "Port Scan", "Web Attack"]
PROTOCOLS = ["TCP", "UDP", "HTTP"]


def random_ip(private=False):
    if private:
        return f"10.0.0.{random.randint(2, 254)}"

    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(2, 254)}"


def generate_event():
    attack = random.choices(
        ATTACK_PATTERNS,
        weights=[45, 15, 15, 15, 10],
        k=1
    )[0]

    if attack == "Normal":
        packet_count = random.randint(40, 180)
        byte_count = random.randint(15000, 70000)
        failed_logins = random.randint(0, 1)
        port_scan_count = random.randint(0, 2)
        request_rate = random.randint(10, 45)
        protocol = random.choice(["TCP", "UDP"])

    elif attack == "DDoS":
        packet_count = random.randint(2400, 5200)
        byte_count = random.randint(700000, 1800000)
        failed_logins = random.randint(0, 2)
        port_scan_count = random.randint(1, 8)
        request_rate = random.randint(500, 1200)
        protocol = random.choice(["TCP", "UDP"])

    elif attack == "Brute Force":
        packet_count = random.randint(500, 1300)
        byte_count = random.randint(160000, 500000)
        failed_logins = random.randint(8, 30)
        port_scan_count = random.randint(1, 10)
        request_rate = random.randint(90, 260)
        protocol = "TCP"

    elif attack == "Port Scan":
        packet_count = random.randint(250, 900)
        byte_count = random.randint(70000, 260000)
        failed_logins = random.randint(0, 3)
        port_scan_count = random.randint(15, 60)
        request_rate = random.randint(60, 180)
        protocol = random.choice(["TCP", "UDP"])

    else:
        packet_count = random.randint(550, 1400)
        byte_count = random.randint(190000, 620000)
        failed_logins = random.randint(1, 6)
        port_scan_count = random.randint(2, 9)
        request_rate = random.randint(180, 420)
        protocol = "HTTP"

    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "source_ip": random_ip(private=False),
        "destination_ip": random_ip(private=True),
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "failed_logins": failed_logins,
        "port_scan_count": port_scan_count,
        "request_rate": request_rate,
        "label": attack
    }


def generate_live_batch(count=12):
    return [generate_event() for _ in range(count)]