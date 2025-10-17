import re
import csv

def parse_snort_log(log_file):
    """
    Parses a Snort alert log file forwarded by syslog and extracts key information.
    
    Args:
        log_file (str): The path to the log file (e.g., /var/log/snort_alerts.log).
        
    Returns:
        list: A list of dictionaries, where each dictionary represents an alert.
    """
    alerts = []
    # UPDATED Regex to capture the components of a syslog-formatted Snort alert
    # This now handles the new timestamp, hostname, and process name.
    log_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}-\d{2}:\d{2})\s"  # 1: Full timestamp
        r"\w+\s+snort:\s+"                                   # Matches "kali snort: " (non-capturing)
        r"\[(\d+:\d+:\d+)\]\s"                                 # 2: Signature ID (GID:SID:REV)
        r"\"(.+?)\"\s.*?"                                    # 3: Message (flexible match for priority field)
        r"{\w+}\s"                                           # Protocol (e.g., {TCP})
        r"([\d\.:]+?):(\d+)?\s->\s"                             # 4: Source IP, 5: Source Port
        r"([\d\.:]+?):(\d+)?"                                # 6: Dest IP, 7: Dest Port
    )

    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = log_pattern.search(line) # Use .search() for more flexibility
                if match:
                    alert = {
                        'timestamp': match.group(1),
                        'signature_id': match.group(2),
                        'message': match.group(3),
                        'source_ip': match.group(4),
                        'source_port': match.group(5) if match.group(5) else 'N/A',
                        'dest_ip': match.group(6),
                        'dest_port': match.group(7) if match.group(7) else 'N/A',
                    }
                    alerts.append(alert)
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file}")
        return []
    except PermissionError:
        print(f"Error: Permission denied to read {log_file}. Try running with 'sudo'.")
        return []
        
    return alerts

def save_to_csv(alerts, csv_file):
    """
    Saves a list of alert dictionaries to a CSV file.
    """
    if not alerts:
        print("No matching alerts found in the log file to save.")
        return
        
    keys = alerts[0].keys()
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(alerts)
        print(f"Successfully saved {len(alerts)} alerts to {csv_file}")
    except PermissionError:
        print(f"Error: Permission denied to write to {csv_file}. Check directory permissions.")


# Main execution
if __name__ == "__main__":
    # Point this to your dedicated snort log file on the Mint machine
    log_file_path = '/var/log/snort_alerts.log'
    csv_output_file = 'snort_alerts.csv'
    
    parsed_alerts = parse_snort_log(log_file_path)
    save_to_csv(parsed_alerts, csv_output_file)

