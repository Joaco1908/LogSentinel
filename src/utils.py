import re 
import os
import json
from datetime import datetime
import requests

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
    
def detect_brute_force(events, threshold):
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

def group_failed_events_by_ip(events, suspicious_ips):
    grouped_events = {}
    for event in events:
        if event['result'] == 'Failed':
            ip = event['ip']
            if ip in suspicious_ips:
                if ip in grouped_events:
                    grouped_events[ip].append(event)
                else:
                    grouped_events[ip] = [event]
    return grouped_events

def save_grouped_events_json(grouped_events, folder="reports"):
    # Create a folder if it doesn't exist
    os.makedirs(folder, exist_ok=True)

    # Generate a filename based on the current date and time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"grouped_failed_events_{timestamp}.json"
    filepath = os.path.join(folder, filename)

    # Save the data to a JSON file
    with open(filepath, 'w') as f:
        json.dump(grouped_events, f, indent=4)

    print(f"[+] Grouped failed events saved to {filepath}")

def geolocate_ip(suspicious_ips):
    geo_data = {}
    for ip in suspicious_ips:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            geo_data[ip] = {
                'country': data['country'],
                'regionName': data['regionName'],
                'city': data['city'],
                'zip': data['zip'],
                'lat': data['lat'],
                'lon': data['lon']
            }
        else:
            geo_data[ip] = {
                'error': "Geolocation failed"
            }
    print(json.dumps(geo_data, indent=4))
    return geo_data

def save_geolocated_ips_json(geo_data, folder="reports"):
    # Create a folder if it doesn't exist
    os.makedirs(folder, exist_ok=True)

    # Generate a filename based on the current date and time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"geolocated_ips_{timestamp}.json"
    filepath = os.path.join(folder, filename)

    # Save the data to a JSON file
    with open(filepath, 'w') as f:
        json.dump(geo_data, f, indent=4)

    print(f"[+] Geolocated IPs saved to {filepath}")
