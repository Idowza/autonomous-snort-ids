import subprocess
import getpass
import os
import shlex
import sys

# --- Configuration ---
KALI_USER = "kali"  # Replace with your actual username
KALI_IP = "192.168.1.44"
REMOTE_RULES_FILE = "/etc/snort/rules/local.rules"
SUGGESTED_RULES_FILE = "suggested_rules.txt"
TEMP_RULE_FILE_REMOTE = f"/tmp/approved_rule_{os.getpid()}.rules" 
USE_SSHPASS = False 

# --- Helper Functions ---

def run_remote_command(command, password=None):
    """Executes a command on the remote Kali machine via SSH."""
    ssh_command = ["ssh", f"{KALI_USER}@{KALI_IP}", command]
    if USE_SSHPASS and password:
        ssh_command = ["sshpass", "-p", password] + ssh_command

    try:
        print(f"  [SSH] Executing: {command}")
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True, timeout=15)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"  [SSH Error] {e.stderr.strip()}")
        return False, e.stderr.strip()
    except Exception as e:
        print(f"  [Error] {e}")
        return False, str(e)

def copy_file_to_remote(local_path, remote_path, password=None):
    """Copies a local file to the remote Kali machine via SCP."""
    scp_command = ["scp", local_path, f"{KALI_USER}@{KALI_IP}:{remote_path}"]
    if USE_SSHPASS and password:
        scp_command = ["sshpass", "-p", password] + scp_command

    try:
        subprocess.run(scp_command, capture_output=True, text=True, check=True, timeout=15)
        print("  [SCP] Copy successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [SCP Error] {e.stderr.strip()}")
        return False

def reload_snort_rules(password=None):
    """Robustly attempts to reload Snort rules."""
    print("\nAttempting to reload Snort rules on Kali...")

    # Method 1: Systemd (Best if running as service)
    # cmd = "sudo systemctl reload snort"
    
    # Method 2: Signal via PID (Best for manual run)
    # We use 'pidof' to find the PID of the snort process
    cmd = "sudo kill -HUP $(pidof snort)"
    
    success, output = run_remote_command(cmd, password)
    
    if success:
        print("  [OK] Snort reload signal sent.")
        return True
    else:
        print(f"  [FAIL] Could not reload Snort. Reason: {output}")
        # Fallback: Try pkill just in case pidof failed
        print("  [INFO] Trying fallback method (pkill)...")
        success, output = run_remote_command("sudo pkill -HUP -f snort", password)
        if success:
             print("  [OK] Fallback reload successful.")
             return True
        
        return False

# --- Rule Parsing Logic ---
def parse_rules_from_file(filepath):
    rules = []
    current_desc = ""
    current_block = []
    
    if not os.path.exists(filepath): return []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            if line.startswith("# Rule for"):
                if current_block:
                    rules.append({'desc': current_desc, 'rule': "\n".join(current_block)})
                    current_block = []
                current_desc = line
            elif line.startswith(('alert', 'log', 'pass', 'drop', 'reject')):
                current_block.append(line)
            elif current_block and line.endswith(';)'): # Handle multiline
                current_block.append(line)

        if current_block:
            rules.append({'desc': current_desc, 'rule': "\n".join(current_block)})
    return rules

# --- Main Logic ---
if __name__ == "__main__":
    kali_password = None
    if USE_SSHPASS:
        kali_password = getpass.getpass(f"Enter password for {KALI_USER}@{KALI_IP}: ")

    parsed_rules = parse_rules_from_file(SUGGESTED_RULES_FILE)
    
    if not parsed_rules:
        print("No new rules to process.")
        sys.exit(0)

    print(f"\n--- Found {len(parsed_rules)} rules to review ---")
    approved = False

    for i, item in enumerate(parsed_rules):
        print(f"\n{item['desc']}")
        print(f"Rule: {item['rule']}")
        
        choice = input("Approve and Deploy? (y/n): ").lower().strip()
        
        if choice == 'y':
            # 1. Write temp file
            temp_local = f"temp_rule_{i}.txt"
            with open(temp_local, 'w') as f: f.write(item['rule'] + "\n")
            
            # 2. Copy and Append
            if copy_file_to_remote(temp_local, TEMP_RULE_FILE_REMOTE, kali_password):
                append_cmd = f"sudo sh -c 'cat {TEMP_RULE_FILE_REMOTE} >> {REMOTE_RULES_FILE}'"
                success, _ = run_remote_command(append_cmd, kali_password)
                
                if success:
                    print(f"  [OK] Rule appended to {REMOTE_RULES_FILE}")
                    approved = True
                    # Clean up
                    run_remote_command(f"sudo rm {TEMP_RULE_FILE_REMOTE}", kali_password)
            
            os.remove(temp_local)
        else:
            print("  [INFO] Rule rejected.")

    if approved:
        if reload_snort_rules(kali_password):
            print("\n[SUCCESS] Rules updated and Snort reloaded.")
        else:
            print("\n[WARNING] Rules updated but Snort failed to reload. Restart manually.")
    
    # Clear file?
    if input("\nClear suggested_rules.txt? (y/n): ").lower() == 'y':
        open(SUGGESTED_RULES_FILE, 'w').close()
        print("File cleared.")