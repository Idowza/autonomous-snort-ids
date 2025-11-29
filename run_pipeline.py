import subprocess
import sys
import time
import os

# --- Configuration ---
# Paths to your Python scripts
SCRIPT_PARSE = "parse_logs.py"
SCRIPT_TRAIN = "train_model.py"
SCRIPT_SUGGEST = "suggest_rule.py"

# Log files to check
LOCAL_SNORT_LOG = "/var/log/snort_alerts.log" # Adjust if needed
PROCESSED_CSV = "snort_alerts.csv"

def run_command(command, description):
    """Runs a shell command and prints status."""
    print(f"\n--- {description} ---")
    start_time = time.time()
    
    try:
        # process = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        # Using Popen to stream output in real-time
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Print stdout in real-time
        for line in process.stdout:
            print(line, end='')
            
        process.wait()
        
        if process.returncode != 0:
            print(f"\n[ERROR] {description} failed with return code {process.returncode}.")
            # Print stderr if failed
            print(process.stderr.read())
            return False
            
    except Exception as e:
        print(f"\n[ERROR] Execution failed: {e}")
        return False

    elapsed = time.time() - start_time
    print(f"\n[SUCCESS] {description} completed in {elapsed:.2f} seconds.")
    return True

def check_requirements():
    """Checks if essential files exist."""
    if not os.path.exists(SCRIPT_PARSE):
        print(f"Error: {SCRIPT_PARSE} not found.")
        return False
    if not os.path.exists(SCRIPT_TRAIN):
        print(f"Error: {SCRIPT_TRAIN} not found.")
        return False
    if not os.path.exists(SCRIPT_SUGGEST):
        print(f"Error: {SCRIPT_SUGGEST} not found.")
        return False
    return True

# --- Main Execution ---
if __name__ == "__main__":
    print("========================================================")
    print("   AI-Enhanced Autonomous IDS - Full Pipeline Execution")
    print("========================================================")
    
    if not check_requirements():
        sys.exit(1)

    # 1. Parse Logs
    # We need sudo for this because /var/log might be restricted
    if not run_command(f"sudo python3 {SCRIPT_PARSE}", "Step 1: Parsing Snort Logs"):
        sys.exit(1)

    # 2. Train Models
    # We pass '0.1' as input to the script to automate the sample rate selection
    # The 'echo 0.1 |' pipes the input to the script's stdin
    if not run_command(f"echo 0.1 | sudo python3 {SCRIPT_TRAIN}", "Step 2: Training AI Models"):
        sys.exit(1)

    # 3. Suggest Rules
    if not run_command(f"python3 {SCRIPT_SUGGEST}", "Step 3: Autonomous Rule Generation"):
        sys.exit(1)

    print("\n========================================================")
    print("   Pipeline Execution Complete")
    print("   Check 'suggested_rules.txt' for new rules.")
    print("========================================================")