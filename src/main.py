import argparse
from utils import parse_log_line, load_logs, detect_brute_force, save_suspicious_ips_json, group_failed_events_by_ip, save_grouped_events_json, geolocate_ip, save_geolocated_ips_json

# Set up argument parser
parser = argparse.ArgumentParser(description="Parse SSH logs and detect brute force attacks.")
parser.add_argument("--logfile", required=True, help="Path to the log file to parse.")
parser.add_argument("--threshold", type=int, default=3, help="Minimum failed attempts to consider an IP suspicious")
parser.add_argument("--geo", action="store_true", help="Enable geolocation of suspicious IPs")
parser.add_argument("--save-json", action="store_true", help="Save results in the reports/ folder")

args = parser.parse_args()

log_file = args.logfile
threshold = args.threshold
geo = args.geo
save_json = args.save_json

events = load_logs(log_file)

print(f"Parsed {len(events)} valid events:")

for event in events:
    print(event)

print(f"\nDetecting brute force attacks with threshold: {threshold}")
print(f"Total events: {len(events)}")

print("\nSuspicious IPs:")
suspicious = detect_brute_force(events, threshold)
for ip, count in suspicious.items():
    print(f"- {ip}: {count} failed attempts")

if save_json:
    # Save suspicious IPs to JSON file
    print("\nSaving suspicious IPs to JSON...") 
    save_suspicious_ips_json(suspicious)
    detailed_report = group_failed_events_by_ip(events, suspicious)
    save_grouped_events_json(detailed_report)

if args.geo:
    # Geolocate suspicious IPs
    print("\nGeolocating suspicious IPs...")
    geo_data = geolocate_ip(suspicious)
    print("\nGeolocated IPs:")
    for ip, location in geo_data.items():
        print(f"- {ip}: {location}")
    save_geolocated_ips_json(geo_data)