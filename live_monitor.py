import time
import subprocess
import os
import sys

# --- Configuration ---
CHECK_INTERVAL = 5  # How often to poll for threats (seconds)
SCRIPT_PARSE = "parse_logs.py"
SCRIPT_SUGGEST = "suggest_rule.py"
SCRIPT_APPROVE = "approve_rules.py"
RULES_FILE = "suggested_rules.txt"

def run_command(command, description):
    """Runs a command and handles errors."""
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"[!] Error during: {description}")
        return False

def check_for_rules():
    """Checks if the rules file exists and is not empty."""
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        return True
    return False

# --- Main Loop ---
if __name__ == "__main__":
    print("========================================================")
    print("   AI-Enhanced IDS - Live Interactive Monitor")
    print("   Scanning for threats every 5 seconds...")
    print("========================================================")

    try:
        while True:
            # 1. Parse Logs (Silent update of CSV)
            # We redirect output to /dev/null to keep the console clean unless there's an error
            subprocess.run(f"sudo python3 {SCRIPT_PARSE} > /dev/null 2>&1", shell=True)
            
            # 2. Run Detection & Suggestion
            # We let this print to console so you see "Analyzing..." messages
            run_command(f"python3 {SCRIPT_SUGGEST}", "Threat Detection")

            # 3. Check for New Rules
            # Only launch the approval tool if the AI actually wrote something to the file
            if check_for_rules():
                print("\n[!] NEW RULES GENERATED - ACTION REQUIRED")
                print(">>> Launching Approval Interface...")
                
                # Run approval script interactively
                run_command(f"python3 {SCRIPT_APPROVE}", "Rule Approval")
                
                print(">>> Returning to Monitoring Mode...")
            
            # Wait for next cycle
            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n[+] Monitor stopped by user.")
        sys.exit(0)