import re
import csv
import os
import sys

def parse_line(line):
    """
    Tries to parse a log line using multiple known Snort formats.
    Returns a dictionary if successful, None otherwise.
    """
    # --- Regex 1: Syslog Format (Live Forwarding) ---
    # Example: 2025-10-16T18:55:48-05:00 kali snort: [1:1000001:1] "Message" ...
    syslog_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}T[\d:\.\-\+]+)\s+"       # Timestamp (ISO 8601)
        r"\S+\s+snort:\s+"                           # Hostname + process
        r"\[(\d+:\d+:\d+)\]\s+"                      # Signature ID
        r"\"(.*?)\"\s+"                              # Message
        r"(?:\[Classification:.*?\]\s+)?(?:\[Priority: \d+\]\s+)?" # Optional Metadata
        r"\{(.*?)\}\s+"                              # Protocol
        r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\s+->\s+" # Source IP : Port (Optional)
        r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?"      # Dest IP : Port (Optional)
    )

    # --- Regex 2: Standard Snort Format (Fast Alert / PCAP Output) ---
    # Example: 10/24-12:00:00.123456 [**] [1:1000...] "Message" ...
    standard_pattern = re.compile(
        r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"   # Timestamp (Snort custom)
        r"\[\*\*\]\s+"                               # Marker
        r"\[(\d+:\d+:\d+)\]\s+"                      # Signature ID
        r"\"(.*?)\"\s+"                              # Message
        r"(?:\[\*\*\]\s+)?"                          # Optional Marker
        r"(?:\[Classification:.*?\]\s+)?(?:\[Priority: \d+\]\s+)?" # Optional Metadata
        r"\{(.*?)\}\s+"                              # Protocol
        r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\s+->\s+" # Source IP : Port
        r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?"      # Dest IP : Port
    )

    # Attempt Match: Syslog
    match = syslog_pattern.search(line)
    if match:
        return {
            'timestamp': match.group(1),
            'signature_id': match.group(2),
            'message': match.group(3),
            'protocol': match.group(4),
            'source_ip': match.group(5),
            'source_port': match.group(6) if match.group(6) else '0', # Default to 0 if no port (e.g. ICMP)
            'dest_ip': match.group(7),
            'dest_port': match.group(8) if match.group(8) else '0'
        }

    # Attempt Match: Standard
    match = standard_pattern.search(line)
    if match:
        return {
            'timestamp': match.group(1),
            'signature_id': match.group(2),
            'message': match.group(3),
            'protocol': match.group(4),
            'source_ip': match.group(5),
            'source_port': match.group(6) if match.group(6) else '0',
            'dest_ip': match.group(7),
            'dest_port': match.group(8) if match.group(8) else '0'
        }
        
    return None

def parse_snort_log_file(log_file_path):
    """Reads a single file and returns a list of parsed alert dicts."""
    alerts = []
    if not os.path.exists(log_file_path):
        print(f"[-] File not found (skipping): {log_file_path}")
        return alerts

    print(f"[+] Parsing {log_file_path}...")
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                alert = parse_line(line)
                if alert:
                    alerts.append(alert)
        print(f"    -> Found {len(alerts)} valid alerts.")
    except PermissionError:
        print(f"    [ERROR] Permission denied reading {log_file_path}. Try running with sudo.")
    return alerts

def save_to_csv(alerts, csv_file):
    if not alerts:
        print("[-] No alerts to save.")
        return
        
    keys = alerts[0].keys()
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(alerts)
        print(f"\n[SUCCESS] Saved {len(alerts)} total alerts to {csv_file}")
    except PermissionError:
        print(f"\n[ERROR] Permission denied writing to {csv_file}.")

# --- Main Execution ---
if __name__ == "__main__":
    # List of files to process
    # 1. The live syslog file
    # 2. The offline PCAP analysis file (we'll name it snort_pcap_alerts.txt)
    input_files = ['/var/log/snort_alerts.log', 'snort_pcap_alerts.txt']
    output_file = 'snort_alerts.csv'
    
    all_alerts = []
    
    for log_file in input_files:
        all_alerts.extend(parse_snort_log_file(log_file))

    save_to_csv(all_alerts, output_file)