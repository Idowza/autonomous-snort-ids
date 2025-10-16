import re
import csv

def parse_snort_log(log_file):
    """
    Parses a Snort snort_alerts.log log file and extracts key information.
    
    Args:
        log_file (str): The path to the snort_alerts.log file.
        
    Returns:
        list: A list of dictionaries, where each dictionary represents an alert.
    """
    alerts = []
    # Regex to capture the main components of a Snort snort_alerts log entry
    log_pattern = re.compile(
        r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s"  # 1: Timestamp
        r"\[\*\*\]\s\[(\d+:\d+:\d+)\]\s"             # 2: Signature ID (GID:SID:REV)
        r"\"(.+?)\"\s"                               # 3: Message
        r"\[\*\*\]\s.+?{\w+}\s"                      # Non-capturing group for protocol
        r"([\d\.:]+?):(\d+)?\s->\s"                  # 4: Source IP, 5: Source Port
        r"([\d\.:]+?):(\d+)?"                       # 6: Dest IP, 7: Dest Port
    )

    with open(log_file, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
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
    return alerts

def save_to_csv(alerts, csv_file):
    """
    Saves a list of alert dictionaries to a CSV file.
    """
    if not alerts:
        print("No alerts to save.")
        return
        
    keys = alerts[0].keys()
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(alerts)
    print(f"Successfully saved {len(alerts)} alerts to {csv_file}")

# Main execution
if __name__ == "__main__":
    parsed_alerts = parse_snort_log('/var/log/snort_alerts.log')
    if parsed_alerts:
        save_to_csv(parsed_alerts, 'snort_alerts.csv')
