import pandas as pd
import ollama
import re
import sys
import os

# --- Configuration ---
INPUT_CSV = 'snort_alerts.csv'
OUTPUT_RULES_FILE = 'mined_rules.rules'
MODEL_NAME = 'llama3.1:8b' # Use 'llama3.1' if available for better results

def generate_snort_rule_prompt(alert_info):
    """
    Constructs a highly specific prompt for Ollama to generate a production-ready Snort rule
    based on historical attack data.
    """
    dst_port = alert_info['dest_port']
    message = alert_info['message']
    
    # Try to find a payload hint if it exists in the message string
    payload_hint = "unknown"
    if "payload=" in str(message):
        try:
            payload_hint = str(message).split("payload=")[1].split(" ")[0]
        except: pass

    prompt = f"""
    You are a Snort 3 expert. Write a strict, production-ready Snort 3 rule to detect this specific type of attack found in our logs.
    
    ATTACK DETAILS:
    - Attack Name: "{message}"
    - Destination Port: {dst_port}
    - Suspected Payload/Signature: "{payload_hint}"

    STRICT REQUIREMENTS:
    1. HEADER: Use 'alert tcp $EXTERNAL_NET any -> $HOME_NET {dst_port}'.
    2. METADATA:
       - msg:"AI-MINED {message}"
       - flow:to_server,established
       - classtype:attempted-admin
       - sid:<generate_unique_id>
       - rev:1
    3. CONTENT: 
       - If a payload hint is provided (not "unknown"), use 'content:"<hint>"; fast_pattern;'.
       - If no payload hint, use specific flags (e.g., 'flags:S;') or flow options appropriate for the attack name.
    4. FORMAT: Output ONLY the raw rule line. No markdown, no explanations.

    CORRECT EXAMPLE:
    alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"AI-MINED SQL Injection"; flow:to_server,established; content:"UNION SELECT"; fast_pattern; classtype:attempted-admin; sid:1000020; rev:1;)

    OUTPUT:
    """
    return prompt

def clean_rule(rule_text):
    """Cleans up the AI output to extract just the Snort rule."""
    # Remove markdown code fences
    rule = rule_text.replace('```', '').replace('snort', '').strip()
    
    # Remove common hallucinations where models explain variables
    rule = re.sub(r'src ip \S+', '', rule, flags=re.IGNORECASE)
    rule = re.sub(r'dst port \S+', '', rule, flags=re.IGNORECASE)
    
    # Ensure single spaces
    rule = re.sub(' +', ' ', rule)
    
    return rule.strip()

# --- Main Execution ---
if __name__ == "__main__":
    print(f"--- Starting Rule Mining from {INPUT_CSV} ---")

    # 1. Load Data
    if not os.path.exists(INPUT_CSV):
        print(f"Error: {INPUT_CSV} not found. Run the training pipeline first.")
        sys.exit(1)
        
    try:
        # Load dataset (handling different versions of CSVs we might have generated)
        df = pd.read_csv(INPUT_CSV)
        
        # Normalize column names just in case
        df.columns = [c.lower().strip() for c in df.columns]
        
        if 'label' not in df.columns:
            print("[INFO] No 'label' column found. Assuming all alerts in this file are malicious.")
            df['label'] = 1
            
        if 'message' not in df.columns:
            print("Error: 'message' column missing from CSV.")
            sys.exit(1)

    except Exception as e:
        print(f"Error loading CSV: {e}")
        sys.exit(1)

    # 2. Filter for Malicious Events Only
    malicious_df = df[df['label'] == 1]
    
    if malicious_df.empty:
        print("No malicious events found in the logs to mine.")
        sys.exit(0)

    # 3. Find Unique Attack Types
    # Group by message and dest_port to differentiate attacks (e.g., generic messages on diff ports)
    unique_attacks = malicious_df.drop_duplicates(subset=['message', 'dest_port'])
    
    print(f"[+] Found {len(unique_attacks)} distinct attack types in the historical data.")
    print(f"[+] Mining rules using {MODEL_NAME}...\n")

    mined_rules = []
    sid_counter = 1000100 # Start SIDs high to avoid conflicts with manual rules

    for index, row in unique_attacks.iterrows():
        attack_name = row['message']
        dst_port = row.get('dest_port', 'any')
        
        # Skip generic/uninformative messages if you want cleaner rules
        if "Generic" in str(attack_name) or "Unknown" in str(attack_name):
            continue

        print(f"   > Analyzing: {attack_name} (Port {dst_port})...")

        alert_info = {
            'message': attack_name,
            'dest_port': dst_port
        }

        # Ask AI for a rule
        try:
            prompt = generate_snort_rule_prompt(alert_info)
            response = ollama.chat(
                model=MODEL_NAME,
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            raw_rule = response['message']['content']
            clean_rule_text = clean_rule(raw_rule)
            
            # Inject our managed SID to ensure uniqueness and correct syntax
            # Remove any AI-hallucinated SID and insert ours
            clean_rule_text = re.sub(r'sid:\s*\d+;', '', clean_rule_text)
            clean_rule_text = clean_rule_text.replace(')', f'; sid:{sid_counter}; rev:1;)')
            
            # Final sanity check: Ensure rule starts with alert
            if clean_rule_text.startswith("alert"):
                mined_rules.append(f"# Based on log: {attack_name}\n{clean_rule_text}")
                print(f"     [OK] Generated SID:{sid_counter}")
                sid_counter += 1
            else:
                print(f"     [SKIP] AI output was not a valid rule: {clean_rule_text[:30]}...")
            
        except Exception as e:
            print(f"     [ERR] Failed to generate rule: {e}")

    # 4. Save to File
    if mined_rules:
        with open(OUTPUT_RULES_FILE, 'w') as f:
            f.write("# AI-Mined Snort Rules\n")
            f.write(f"# Generated from {INPUT_CSV} analysis\n")
            f.write("# These rules use $HOME_NET and $EXTERNAL_NET variables.\n\n")
            f.write("\n\n".join(mined_rules))
        
        print(f"\n[SUCCESS] Mined {len(mined_rules)} new rules.")
        print(f"rules saved to: {OUTPUT_RULES_FILE}")
        print("Review them, then append to local.rules to deploy.")
    else:
        print("\n[WARN] No rules were generated.")