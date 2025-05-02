import re 
import os
import json
from datetime import datetime

def parse_log_line(line):
    pattern = r'^(?P<date>\w+\s+\d+\s[\d:]+).*?(?P<result>Failed|Accepted).*?password for (invalid user )?(?P<user>\w+).*?from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'

    match = re.search(pattern, line)
    if match:
        return match.groupdict()
    return None

def load_logs(file_path):
    parsed_logs = []
    with open(file_path, 'r') as file_:
        logs = file_.readlines()
        for log in logs:
            result = parse_log_line(log)
            if result:
                parsed_logs.append(result)
        return parsed_logs
    
def detect_brute_force(events, threshold=3):
    ip_fail_count = {}
    for event in events:
        if event['result'] == 'Failed':
            ip = event['ip']
            if ip in ip_fail_count:
                ip_fail_count[ip] += 1
            else:
                ip_fail_count[ip] = 1

    suspicious_ips = {}
    for ip, count in ip_fail_count.items():
        if count >= threshold:
            suspicious_ips[ip] = count
    
    return suspicious_ips

def save_suspicious_ips_json(data, folder="reports"):
    # Create a folder if it doesn't exist
    os.makedirs(folder, exist_ok=True)

    # Generate a filename based on the current date and time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"suspicious_ips_{timestamp}.json"
    filepath = os.path.join(folder, filename)

    # Save the data to a JSON file

    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

    print(f"[+] Suspicious IPs saved to {filepath}")

