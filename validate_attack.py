import subprocess
import time
import sys
import argparse

# --- Configuration ---
KALI_USER = "kali"           # Change if different
KALI_IP = "192.168.1.44"     # Snort Sensor IP
SNORT_LOG = "/var/log/snort/alert_fast.txt" # Location of Snort logs

def run_ssh_command(command):
    """Runs a command on the Kali machine via SSH and returns output."""
    ssh_cmd = f"ssh {KALI_USER}@{KALI_IP} \"{command}\""
    try:
        result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] SSH Error: {e}")
        return None

def get_log_line_count():
    """Gets the current number of lines in the Snort log file."""
    output = run_ssh_command(f"wc -l {SNORT_LOG}")
    if output:
        try:
            return int(output.split()[0])
        except IndexError:
            pass
    return 0

def check_for_new_alerts(start_line, expected_sid):
    """
    Reads the log file starting from 'start_line' and looks for the SID.
    """
    # Read from the next line onwards
    cmd = f"tail -n +{start_line + 1} {SNORT_LOG}"
    new_logs = run_ssh_command(cmd)
    
    if not new_logs:
        return False, "No new logs found."
        
    # Check if the specific SID is present
    # Snort fast logs usually look like: [**] [1:1000005:1] ...
    sid_pattern = f":{expected_sid}:"
    
    if sid_pattern in new_logs:
        # Find the exact line for display
        for line in new_logs.splitlines():
            if sid_pattern in line:
                return True, line
    
    return False, new_logs

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
    print(f"Target Sensor: {KALI_IP}")
    print(f"Expected SID:  {args.sid}")
    
    # 1. Snapshot Log State
    print("\n[1] Checking initial sensor state...")
    initial_count = get_log_line_count()
    print(f"    Current log lines: {initial_count}")

    # 2. Launch Attack
    print("\n[2] Executing Attack...")
    launch_attack(args.cmd)
    
    # 3. Wait for processing
    print("\n[3] Waiting for Snort to process (5s)...")
    time.sleep(5)

    # 4. Verify
    print("\n[4] Verifying Detection...")
    success, details = check_for_new_alerts(initial_count, args.sid)

    if success:
        print("\n[SUCCESS] Validation Passed! Rule Triggered.")
        print(f"Captured Alert: {details}")
    else:
        print("\n[FAILURE] Validation Failed. Rule did not trigger.")
        print("New logs seen (if any):")
        print(details if details else "    (None)")