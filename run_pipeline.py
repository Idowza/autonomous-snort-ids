import subprocess
import sys
import time
import os

# --- Configuration ---
# Paths to your Python scripts
SCRIPT_PARSE = "parse_logs.py"
SCRIPT_TRAIN = "train_model.py"
SCRIPT_SUGGEST = "suggest_rule.py"
SCRIPT_APPROVE = "approve_rules.py"

# Log files to check
LOCAL_SNORT_LOG = "/var/log/snort_alerts.log" 
PROCESSED_CSV = "snort_alerts.csv"

def run_command(command, description, interactive=False):
    """Runs a shell command and prints status."""
    print(f"\n--- {description} ---")
    start_time = time.time()
    
    try:
        if interactive:
            # For interactive scripts, let them take over the terminal
            result = subprocess.run(command, shell=True)
            if result.returncode != 0:
                print(f"\n[ERROR] {description} failed (User interrupted or error).")
                return False
        else:
            # For non-interactive, stream output
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                print(line, end='')
                
            process.wait()
            
            if process.returncode != 0:
                print(f"\n[ERROR] {description} failed with return code {process.returncode}.")
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
    scripts = [SCRIPT_PARSE, SCRIPT_TRAIN, SCRIPT_SUGGEST, SCRIPT_APPROVE]
    missing = [s for s in scripts if not os.path.exists(s)]
    
    if missing:
        for s in missing:
            print(f"Error: {s} not found.")
        return False
    return True

# --- Main Execution ---
if __name__ == "__main__":
    print("========================================================")
    print("   AI-Enhanced Autonomous IDS - Full Pipeline Execution")
    print("========================================================")
    
    if not check_requirements():
        sys.exit(1)

    # 1. Parse Logs (Requires sudo, non-interactive)
    if not run_command(f"sudo python3 {SCRIPT_PARSE}", "Step 1: Parsing Snort Logs"):
        sys.exit(1)

    # 2. Train Models (Interactive - User sets sample rate)
    # Removed 'echo 0.1 |' and set interactive=True so user can type input
    if not run_command(f"sudo python3 {SCRIPT_TRAIN}", "Step 2: Training AI Models", interactive=True):
        sys.exit(1)

    # 3. Suggest Rules (Non-interactive)
    if not run_command(f"python3 {SCRIPT_SUGGEST}", "Step 3: Autonomous Rule Generation"):
        sys.exit(1)

    # 4. Approve & Deploy Rules (Interactive)
    if not run_command(f"python3 {SCRIPT_APPROVE}", "Step 4: Human-in-the-Loop Approval", interactive=True):
        sys.exit(1)

    print("\n========================================================")
    print("   Pipeline Execution Complete")
    print("========================================================")