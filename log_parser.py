# -*- coding: utf-8 -*-
"""
Snort Alert Log Parser

This script reads a Snort 'alert.fast' log file, parses each line to extract
key information, and writes the structured data to a CSV file. This is the
first step in preparing the data for machine learning analysis.
"""

import csv
import re
import os

def parse_snort_log(log_file_path, csv_file_path):
    """
    Parses a Snort alert.fast log file and converts it to a CSV format.

    Args:
        log_file_path (str): The full path to the input alert.fast log file.
        csv_file_path (str): The full path for the output CSV file.
    """
    # This updated regular expression is more flexible.
    # The port number capture groups are now optional `(?::(\S+))?` to handle
    # protocols like ICMP or ARP that do not have ports in their log entries.
    log_pattern = re.compile(
        r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # Group 1: Timestamp
        r'\[\*\*\]\s+'
        r'\[(\d+:\d+:\d+)\]\s+'                      # Group 2: Signature ID (GID:SID:REV)
        r'"([^"]+)"\s+'                              # Group 3: Alert Message
        r'\[\*\*\]\s+'
        r'(?:\[Classification:\s*([^\]]+)\]\s+)?'    # Group 4: Optional Classification
        r'\[Priority:\s*(\d+)\]\s+'                  # Group 5: Priority
        r'\{([^}]+)\}\s+'                            # Group 6: Protocol
        r'([\d\.]+)(?::(\S+))?\s+'                    # Group 7 & 8: Source IP and optional Port
        r'->\s+'
        r'([\d\.]+)(?::(\S+))?'                       # Group 9 & 10: Destination IP and optional Port
    )

    # Define the headers for our CSV file
    csv_headers = [
        'timestamp', 'signature_id', 'alert_message', 'classification',
        'priority', 'protocol', 'source_ip', 'source_port',
        'destination_ip', 'destination_port'
    ]

    print(f"Starting to parse log file: {log_file_path}")

    # Use a try-except block to handle potential file errors
    try:
        # Open the input log file for reading and the output CSV for writing
        with open(log_file_path, 'r') as log_file, \
             open(csv_file_path, 'w', newline='') as csv_file:

            writer = csv.writer(csv_file)
            # Write the header row to the CSV file
            writer.writerow(csv_headers)

            parsed_count = 0
            # Read the log file line by line
            for line in log_file:
                # Try to match our regex pattern against the current line
                match = log_pattern.search(line)
                if match:
                    # If it matches, extract all captured groups
                    writer.writerow(match.groups())
                    parsed_count += 1
                else:
                    print(f"Warning: Could not parse line: {line.strip()}")
        
        print(f"\nParsing complete.")
        print(f"Successfully parsed {parsed_count} alert(s).")
        print(f"Data saved to: {csv_file_path}")

    except FileNotFoundError:
        print(f"Error: Log file not found at '{log_file_path}'")
        print("Please ensure the path is correct and the file exists.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    # Define the location of your Snort log file and desired output CSV
    # Make sure to run this script in a location where you have permission to write files,
    # or provide full paths.
    log_directory = '/var/log/snort'
    # CORRECTED FILENAME
    log_filename = 'alert_fast.txt'
    log_path = os.path.join(log_directory, log_filename)
    
    csv_filename = 'snort_alerts.csv'
    csv_path = os.path.join(os.getcwd(), csv_filename)

    parse_snort_log(log_path, csv_path)

