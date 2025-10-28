import subprocess
import getpass
import os
import shlex

# --- Configuration ---
KALI_USER = "your_kali_username"  # Replace with your actual username on the Kali machine
KALI_IP = "192.168.1.44"
REMOTE_RULES_FILE = "/etc/snort/rules/local.rules"
SUGGESTED_RULES_FILE = "suggested_rules.txt"
TEMP_RULE_FILE_REMOTE = f"/tmp/approved_rule_{os.getpid()}.rules" # Unique temp file on Kali
USE_SSHPASS = False # Set to True if you want to use sshpass instead of SSH keys

# --- Helper Functions ---

def run_remote_command(command, password=None):
    """Executes a command on the remote Kali machine via SSH."""
    ssh_command = ["ssh", f"{KALI_USER}@{KALI_IP}", command]
    sshpass_command = ["sshpass", "-p", password] + ssh_command if USE_SSHPASS and password else ssh_command
    
    try:
        print(f"  Executing on Kali: {' '.join(shlex.quote(c) for c in ssh_command)}") # Show command without password
        result = subprocess.run(sshpass_command, capture_output=True, text=True, check=True)
        print(f"  Success: {result.stdout.strip() or '(No output)'}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error executing command on Kali: {e}")
        print(f"  Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print(f"  Error: {'sshpass' if USE_SSHPASS else 'ssh'} command not found. Is it installed?")
        return False
    except Exception as e:
        print(f"  An unexpected error occurred: {e}")
        return False

def copy_file_to_remote(local_path, remote_path, password=None):
    """Copies a local file to the remote Kali machine via SCP."""
    scp_command = ["scp", local_path, f"{KALI_USER}@{KALI_IP}:{remote_path}"]
    sshpass_command = ["sshpass", "-p", password] + scp_command if USE_SSHPASS and password else scp_command

    try:
        print(f"  Copying rule to Kali: {remote_path}")
        result = subprocess.run(sshpass_command, capture_output=True, text=True, check=True)
        # SCP doesn't usually produce stdout on success
        if result.returncode == 0:
             print("  Copy successful.")
             return True
        else:
            print(f"  Error copying file: {result.stderr.strip()}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"  Error copying file to Kali: {e}")
        print(f"  Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
         print(f"  Error: {'sshpass' if USE_SSHPASS else 'scp'} command not found. Is it installed?")
         return False
    except Exception as e:
        print(f"  An unexpected error occurred: {e}")
        return False

def reload_snort_rules():
    """Attempts to reload Snort rules on the remote Kali machine."""
    # Snort 3 doesn't have a simple reload command like older versions.
    # The most reliable way is often to find the process ID (PID) and send SIGHUP.
    # Alternatively, if running as a service, systemctl might work.
    
    # Try finding PID and sending SIGHUP first
    print("\nAttempting to reload Snort rules on Kali...")
    command_find_pid = "pgrep -f 'snort -c /etc/snort/snort.lua'" # Adjust if your start command differs
    
    try:
        # Use subprocess directly to capture PID output easily
        ssh_command = ["ssh", f"{KALI_USER}@{KALI_IP}", command_find_pid]
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        pids = result.stdout.strip().split()
        
        if pids:
            # Send SIGHUP to the first PID found
            pid = pids[0]
            print(f"  Found Snort PID: {pid}. Sending SIGHUP to reload rules.")
            reload_command = f"sudo kill -HUP {pid}"
            if run_remote_command(reload_command):
                 print("  Snort reload signal sent successfully.")
                 return True
            else:
                 print("  Failed to send SIGHUP signal.")
                 return False
        else:
            print("  Could not find running Snort process via pgrep.")
            # Fallback: Try systemctl if Snort is run as a service (less likely on manual start)
            # print("  Attempting fallback: systemctl reload snort3...") # Or appropriate service name
            # reload_command_systemd = "sudo systemctl reload snort3" # Adjust service name if needed
            # return run_remote_command(reload_command_systemd)
            print("  Could not reload Snort automatically. You may need to restart Snort manually.")
            return False

    except subprocess.CalledProcessError:
        print("  Could not find Snort process or error checking PID.")
        print("  Could not reload Snort automatically. You may need to restart Snort manually.")
        return False
    except FileNotFoundError:
         print(f"  Error: ssh command not found. Is it installed?")
         return False

# --- Main Logic ---
if __name__ == "__main__":
    
    kali_password = None
    if USE_SSHPASS:
        kali_password = getpass.getpass(f"Enter password for {KALI_USER}@{KALI_IP}: ")

    approved_rules_content = []
    rejected_count = 0
    processed_count = 0

    try:
        with open(SUGGESTED_RULES_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: '{SUGGESTED_RULES_FILE}' not found. No rules to process.")
        exit()

    current_rule_lines = []
    description_line = ""

    print(f"\n--- Reviewing Suggested Snort Rules from {SUGGESTED_RULES_FILE} ---")

    for line in lines:
        line = line.strip()
        if not line: # Skip empty lines
             continue
        
        if line.startswith("# Rule for alert:"):
            description_line = line # Store the description
        elif line.startswith(('alert', 'block', 'pass', 'drop')): # Basic check for a rule start
            current_rule_lines.append(line)
        else: # Assume multi-line rule or comment related to previous rule
            if current_rule_lines:
                 current_rule_lines.append(line)

        # Heuristic: Assume rule ends if the line looks like a complete rule ending with ');' or if followed by description
        if current_rule_lines and (line.endswith(');') or line.startswith("# Rule for alert:") or line == lines[-1].strip()):
            processed_count += 1
            full_rule = "\n".join(current_rule_lines)
            
            print("\n----------------------------------------")
            if description_line:
                print(f"Description: {description_line}")
            print(f"Suggested Rule #{processed_count}:")
            print(full_rule)
            print("----------------------------------------")

            while True:
                approve = input("Approve this rule? (y/n): ").lower().strip()
                if approve in ['y', 'yes']:
                    approved_rules_content.append(full_rule)
                    # Write rule to a temporary local file
                    temp_local_file = f"/tmp/rule_{processed_count}.temp"
                    try:
                        with open(temp_local_file, "w") as temp_f:
                            temp_f.write(full_rule + "\n") # Ensure newline at the end

                        # Copy temp file to remote
                        if copy_file_to_remote(temp_local_file, TEMP_RULE_FILE_REMOTE, kali_password):
                            # Append from temp file on remote to actual rules file
                            append_command = f"sudo sh -c 'cat {TEMP_RULE_FILE_REMOTE} >> {REMOTE_RULES_FILE}'"
                            if run_remote_command(append_command, kali_password):
                                print(f"Rule #{processed_count} approved and appended to {REMOTE_RULES_FILE} on Kali.")
                            else:
                                print(f"Error: Failed to append rule #{processed_count} on Kali.")
                            # Clean up temp file on remote
                            run_remote_command(f"rm {TEMP_RULE_FILE_REMOTE}", kali_password)
                        else:
                            print(f"Error: Failed to copy rule #{processed_count} to Kali.")
                            
                    except IOError as e:
                        print(f"Error writing temporary local file: {e}")
                    finally:
                        if os.path.exists(temp_local_file):
                            os.remove(temp_local_file) # Clean up local temp file
                            
                    break
                elif approve in ['n', 'no']:
                    print(f"Rule #{processed_count} rejected.")
                    rejected_count += 1
                    break
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")

            # Reset for the next rule
            current_rule_lines = []
            description_line = ""
            # If the current line started a new rule description, process it now
            if line.startswith("# Rule for alert:"):
                 description_line = line
            

    approved_count = len(approved_rules_content)
    print(f"\n--- Review Complete ---")
    print(f"Processed: {processed_count} rules")
    print(f"Approved:  {approved_count} rules")
    print(f"Rejected:  {rejected_count} rules")

    if approved_count > 0:
        if not reload_snort_rules():
            print("\nManual Action Required: Please restart Snort on the Kali machine to apply the new rules.")
        else:
             print("\nSnort rules successfully reloaded on Kali.")


    # Optionally clear the suggestions file
    clear_file = input("\nClear the suggested_rules.txt file? (y/n): ").lower().strip()
    if clear_file in ['y', 'yes']:
        try:
            with open(SUGGESTED_RULES_FILE, 'w') as f:
                f.write("") # Overwrite with empty content
            print(f"'{SUGGESTED_RULES_FILE}' has been cleared.")
        except IOError as e:
            print(f"Error clearing file: {e}")