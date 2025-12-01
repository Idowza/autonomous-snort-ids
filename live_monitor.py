import time
import subprocess
import os

# --- Configuration ---
CHECK_INTERVAL = 10  # Check every 10 seconds
SCRIPT_SUGGEST = "suggest_rule.py"
SCRIPT_PARSE = "parse_logs.py" # Need to parse latest logs first!
SCRIPT_TRAIN = "train_model.py" # Optional: Retrain if you want continuous learning

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {command}: {e}")

print("--- Starting Live Threat Monitor ---")
print("Press Ctrl+C to stop.")

try:
    while True:
        print(f"\n[+] Checking for new alerts ({time.strftime('%X')})...")
        
        # 1. Parse the latest logs from Snort/Syslog
        # This updates snort_alerts.csv with any new data
        run_command(f"sudo python3 {SCRIPT_PARSE}")
        
        # 2. (Optional) Retrain models on the very latest data
        # run_command(f"echo 0.1 | sudo python3 {SCRIPT_TRAIN}") 

        # 3. Run the Suggest Rule script
        # Note: suggest_rule.py currently processes a *simulated* alert.
        # To make it truly live, suggest_rule.py needs to read the *latest* # real alert from snort_alerts.csv instead of the hardcoded one.
        run_command(f"python3 {SCRIPT_SUGGEST}")
        
        time.sleep(CHECK_INTERVAL)

except KeyboardInterrupt:
    print("\n--- Monitor Stopped ---")