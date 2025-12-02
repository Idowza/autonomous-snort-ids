import subprocess
import time
import sys
import argparse
import os

# --- Configuration ---
# Validate against the local log file on Mint (where alerts are forwarded)
SNORT_LOG = "/var/log/snort_alerts.log" 

def get_log_position():
    """Gets the current file pointer position (end of file)."""
    try:
        with open(SNORT_LOG, 'r') as f:
            f.seek(0, os.SEEK_END)
            return f.tell()
    except FileNotFoundError:
        print(f"[!] Error: Log file {SNORT_LOG} not found.")
        return 0

def check_for_new_alerts(start_pos, expected_sid):
    """
    Reads the log file starting from 'start_pos' and looks for the SID.
    """
    try:
        with open(SNORT_LOG, 'r') as f:
            f.seek(start_pos)
            new_logs = f.read()
            
        if not new_logs:
            return False, "No new logs found."
            
        # Check if the specific SID is present
        # Syslog format often includes [1:SID:Rev]
        sid_pattern = f":{expected_sid}:"
        
        if sid_pattern in new_logs:
            for line in new_logs.splitlines():
                if sid_pattern in line:
                    return True, line
        
        return False, new_logs
    except Exception as e:
        return False, str(e)

def launch_attack(attack_cmd):
    """Executes the attack command locally on Mint."""
    print(f"\n[+] Launching Attack: {attack_cmd}")
    try:
        # Run the attack, wait for it to finish (or timeout if it's a flood)
        subprocess.run(attack_cmd, shell=True, timeout=15)
    except subprocess.TimeoutExpired:
        print("    (Attack command timed out - this is normal for floods)")
    except Exception as e:
        print(f"    [!] Error running attack: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate Snort Rules by Replaying Attacks")
    parser.add_argument("--cmd", required=True, help="The attack command to run (in quotes)")
    parser.add_argument("--sid", required=True, help="The Snort SID expected to trigger")
    
    args = parser.parse_args()

    print("==========================================")
    print("   Automated Rule Validation System")
    print("==========================================")
    print(f"Log Source:    {SNORT_LOG}")
    print(f"Expected SID:  {args.sid}")
    
    # 1. Snapshot Log State
    print("\n[1] Checking initial log state...")
    initial_pos = get_log_position()
    print(f"    Current log size: {initial_pos} bytes")

    # 2. Launch Attack
    print("\n[2] Executing Attack...")
    launch_attack(args.cmd)
    
    # 3. Wait for processing (Network latency + Rsyslog delay)
    print("\n[3] Waiting for logs to arrive (5s)...")
    time.sleep(5)

    # 4. Verify
    print("\n[4] Verifying Detection...")
    success, details = check_for_new_alerts(initial_pos, args.sid)

    if success:
        print("\n[SUCCESS] Validation Passed! Rule Triggered.")
        print(f"Captured Alert: {details}")
    else:
        print("\n[FAILURE] Validation Failed. Rule did not trigger.")
        print("New logs seen (if any):")
        print(details if details else "    (None)")