import argparse
from utils import parse_log_line, load_logs, detect_brute_force, save_suspicious_ips_json

# Set up argument parser
parser = argparse.ArgumentParser(description="Parse SSH logs and detect brute force attacks.")
parser.add_argument("--logfile", required=True, help="Path to the log file to parse.")
args = parser.parse_args()

log_file = args.logfile

events = load_logs(log_file)

print(f"Parsed {len(events)} valid events:")

for event in events:
    print(event)

print("\nSuspicious IPs:")
suspicious = detect_brute_force(events, threshold=3)
for ip, count in suspicious.items():
    print(f"- {ip}: {count} failed attempts")

save_suspicious_ips_json(suspicious)