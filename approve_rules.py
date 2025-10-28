import subprocess
import getpass
import os
import shlex
import sys # For exiting early

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
    ssh_command_base = ["ssh", f"{KALI_USER}@{KALI_IP}"]
    # Need to handle commands with spaces correctly, especially sudo
    full_command_str = command # Assume command is a single string for simplicity here
    ssh_command = ssh_command_base + [full_command_str]

    sshpass_command = ["sshpass", "-p", password] + ssh_command if USE_SSHPASS and password else ssh_command

    try:
        # Show command without password for security
        print(f"  Executing on Kali: ssh {KALI_USER}@{KALI_IP} '{full_command_str}'")
        result = subprocess.run(sshpass_command, capture_output=True, text=True, check=True, timeout=30)
        print(f"  Success: {result.stdout.strip() or '(No output)'}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error executing command on Kali: {e}")
        print(f"  Stderr: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        print("  Error: SSH command timed out.")
        return False
    except FileNotFoundError:
        print(f"  Error: {'sshpass' if USE_SSHPASS else 'ssh'} command not found. Is it installed and in PATH?")
        return False
    except Exception as e:
        print(f"  An unexpected error occurred during remote command execution: {e}")
        return False

def copy_file_to_remote(local_path, remote_path, password=None):
    """Copies a local file to the remote Kali machine via SCP."""
    scp_command = ["scp", local_path, f"{KALI_USER}@{KALI_IP}:{remote_path}"]
    sshpass_command = ["sshpass", "-p", password] + scp_command if USE_SSHPASS and password else scp_command

    try:
        print(f"  Copying rule to Kali ({remote_path})...")
        result = subprocess.run(sshpass_command, capture_output=True, text=True, check=True, timeout=30)
        # SCP doesn't usually produce stdout on success
        if result.returncode == 0:
             print("  Copy successful.")
             return True
        # Note: check=True raises CalledProcessError on non-zero exit, so else might not be reached often
        else:
            print(f"  Error copying file (Return Code {result.returncode}): {result.stderr.strip()}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"  Error copying file to Kali: {e}")
        print(f"  Stderr: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        print("  Error: SCP command timed out.")
        return False
    except FileNotFoundError:
         print(f"  Error: {'sshpass' if USE_SSHPASS else 'scp'} command not found. Is it installed and in PATH?")
         return False
    except Exception as e:
        print(f"  An unexpected error occurred during file copy: {e}")
        return False

def reload_snort_rules(password=None):
    """Attempts to reload Snort rules on the remote Kali machine."""
    print("\nAttempting to reload Snort rules on Kali...")
    # Using pkill with the full command path might be more robust if snort path is known
    # Example: command_find_pid = "pgrep -f '/usr/local/bin/snort -c /etc/snort/snort.lua'"
    # Trying a simpler pgrep first
    command_find_pid = "pgrep -f snort" # More general

    ssh_command = ["ssh", f"{KALI_USER}@{KALI_IP}", command_find_pid]
    sshpass_find_cmd = ["sshpass", "-p", password] + ssh_command if USE_SSHPASS and password else ssh_command

    try:
        result = subprocess.run(sshpass_find_cmd, capture_output=True, text=True, check=True, timeout=10)
        pids = result.stdout.strip().split()

        if pids:
            # Send SIGHUP to the first PID found
            pid = pids[0]
            print(f"  Found Snort PID(s): {', '.join(pids)}. Sending SIGHUP to PID {pid}.")
            # IMPORTANT: Ensure the user running this script has sudo privileges on Kali WITHOUT password prompt for kill,
            # OR run the snort process under the same user you SSH as, OR adjust sudoers.
            reload_command = f"sudo kill -HUP {pid}"
            if run_remote_command(reload_command, password): # Pass password if using sshpass
                 print("  Snort reload signal (SIGHUP) sent successfully.")
                 return True
            else:
                 print("  Failed to send SIGHUP signal via SSH.")
                 return False
        else:
            print("  Could not find running Snort process via pgrep.")
            print("  Cannot reload automatically. You may need to restart Snort manually on Kali.")
            return False

    except subprocess.CalledProcessError:
        print("  Could not find Snort process via pgrep (or error running command).")
        print("  Cannot reload automatically.")
        return False
    except subprocess.TimeoutExpired:
         print("  Error: SSH command to find PID timed out.")
         return False
    except FileNotFoundError:
         print(f"  Error: {'sshpass' if USE_SSHPASS else 'ssh'} command not found.")
         return False
    except Exception as e:
        print(f"  An unexpected error occurred during Snort reload attempt: {e}")
        return False


# --- Rule Parsing Logic ---
def parse_rules_from_file(filepath):
    """Parses descriptions and associated rule blocks from the file."""
    rules = []
    current_description = "No description found"
    current_rule_lines = []
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: '{filepath}' not found. No rules to process.")
        return [] # Return empty list

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line: # Skip empty lines
            continue

        if stripped_line.startswith("# Rule for alert:"):
            # If we were accumulating rule lines, save the previous rule block first
            if current_rule_lines:
                rules.append({"description": current_description, "rule": "\n".join(current_rule_lines)})
            # Start new block
            current_description = stripped_line
            current_rule_lines = []
        elif not stripped_line.startswith("#"): # Accumulate non-comment lines as part of the rule
             current_rule_lines.append(stripped_line)
        # Implicitly ignore other comment lines unless needed

    # Add the last rule block if any lines were accumulated
    if current_rule_lines:
        rules.append({"description": current_description, "rule": "\n".join(current_rule_lines)})

    return rules


# --- Main Logic ---
if __name__ == "__main__":

    kali_password = None
    if USE_SSHPASS:
        try:
            kali_password = getpass.getpass(f"Enter password for {KALI_USER}@{KALI_IP}: ")
        except Exception as e:
            print(f"Error getting password: {e}")
            sys.exit(1)


    parsed_rules = parse_rules_from_file(SUGGESTED_RULES_FILE)
    processed_count = len(parsed_rules)
    approved_count = 0
    rejected_count = 0
    rules_appended_successfully = False

    print(f"\n--- Found {processed_count} potential rule blocks to review from {SUGGESTED_RULES_FILE} ---")

    if processed_count == 0:
        print("No rules parsed. Exiting.")
        sys.exit(0) # Exit cleanly if no rules found

    for i, rule_block in enumerate(parsed_rules):
        rule_number = i + 1
        print("\n----------------------------------------")
        print(f"{rule_block['description']}")
        print(f"Suggested Rule #{rule_number}:")
        print(rule_block['rule'])
        print("----------------------------------------")

        while True:
            approve = input(f"Approve Rule #{rule_number}? (y/n): ").lower().strip()
            if approve in ['y', 'yes']:
                # Write rule to a temporary local file
                temp_local_file = f"/tmp/rule_{rule_number}_{os.getpid()}.temp" # More unique name
                try:
                    with open(temp_local_file, "w") as temp_f:
                        temp_f.write(rule_block['rule'] + "\n") # Ensure newline

                    # Copy temp file to remote
                    if copy_file_to_remote(temp_local_file, TEMP_RULE_FILE_REMOTE, kali_password):
                        # Append from temp file on remote to actual rules file
                        # Use sh -c for redirection, ensure proper quoting
                        append_command = f"sudo sh -c 'cat {shlex.quote(TEMP_RULE_FILE_REMOTE)} >> {shlex.quote(REMOTE_RULES_FILE)}'"
                        if run_remote_command(append_command, kali_password):
                            print(f"Rule #{rule_number} approved and appended to {REMOTE_RULES_FILE} on Kali.")
                            approved_count += 1
                            rules_appended_successfully = True # Mark that at least one rule was added
                        else:
                            print(f"Error: Failed to append rule #{rule_number} on Kali.")
                        # Clean up temp file on remote *regardless* of append success
                        run_remote_command(f"rm -f {shlex.quote(TEMP_RULE_FILE_REMOTE)}", kali_password)
                    else:
                        print(f"Error: Failed to copy rule #{rule_number} to Kali.")

                except IOError as e:
                    print(f"Error writing temporary local file: {e}")
                finally:
                    # Clean up local temp file
                    if os.path.exists(temp_local_file):
                        try:
                            os.remove(temp_local_file)
                        except OSError as e:
                            print(f"Warning: Could not remove temporary local file {temp_local_file}: {e}")
                break # Exit approval loop

            elif approve in ['n', 'no']:
                print(f"Rule #{rule_number} rejected.")
                rejected_count += 1
                break # Exit approval loop
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

    # --- Summary and Reload ---
    print(f"\n--- Review Complete ---")
    print(f"Total Rules Processed: {processed_count}")
    print(f"Rules Approved:        {approved_count}")
    print(f"Rules Rejected:        {rejected_count}")

    if rules_appended_successfully: # Only try to reload if rules were actually changed
        if not reload_snort_rules(kali_password):
            print("\nWARNING: Snort rules may not have reloaded automatically.")
            print("Manual Action Required: Please restart or reload Snort manually on the Kali machine to apply the new rules.")
        else:
             print("\nSnort reload signal sent. Check Snort logs on Kali for confirmation.")
    else:
        print("\nNo rules were approved, skipping Snort reload attempt.")


    # Optionally clear the suggestions file
    if processed_count > 0: # Only ask if there was something to process
        try:
            clear_file = input(f"\nClear the '{SUGGESTED_RULES_FILE}' file? (y/n): ").lower().strip()
            if clear_file in ['y', 'yes']:
                with open(SUGGESTED_RULES_FILE, 'w') as f:
                    f.write("") # Overwrite with empty content
                print(f"'{SUGGESTED_RULES_FILE}' has been cleared.")
        except Exception as e: # Catch potential input errors or file errors
            print(f"Could not clear file or invalid input: {e}")