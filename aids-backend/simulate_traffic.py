import requests
import time
import random

API_URL = "http://localhost:8000/api/v1/traffic"

def generate_packet():
    is_anomaly = random.random() < 0.3
    
    if is_anomaly:
        proto = random.choice([6, 17, 1])
        length = random.randint(1200, 4000) # Unusual packet size
        is_tcp = 1 if proto == 6 else 0
        is_udp = 1 if proto == 17 else 0
        is_icmp = 1 if proto == 1 else 0
    else:
        proto = random.choice([6, 17])
        length = random.randint(64, 512)
        is_tcp = 1 if proto == 6 else 0
        is_udp = 1 if proto == 17 else 0
        is_icmp = 0

    return {
        "src_ip": f"192.168.1.{random.randint(2, 254)}",
        "dst_ip": f"10.0.0.{random.randint(2, 50)}",
        "proto": proto,
        "length": length,
        "is_tcp": is_tcp,
        "is_udp": is_udp,
        "is_icmp": is_icmp
    }

def main():
    print(f"Starting traffic simulation targeting {API_URL}...")
    print("Press Ctrl+C to stop.\n")
    count = 0
    while True:
        try:
            packet = generate_packet()
            res = requests.post(API_URL, json=packet, timeout=2)
            data = res.json()
            is_anomaly = data.get("anomaly")
            attack_type = data.get("attack_type", "Normal Baseline")
            explanation = data.get("explanation", {})
            confidence = data.get("confidence", 0)

            if is_anomaly:
                print(f"[{count}] 🚨 THREAT: {attack_type} from {packet['src_ip']} (Confidence: {confidence:.2f})")
                print(f"    ↳ XAI Reason: {explanation.get('reason')}")
            else:
                print(f"[{count}] ✓ Safe Packet from {packet['src_ip']} -> {attack_type}")
        except Exception as e:
            print(f"Error sending traffic packet: {e}")
        time.sleep(1)

if __name__ == "__main__":
    main()
