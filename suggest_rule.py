import joblib
import ollama
import pandas as pd
import re
import sys
import os

# --- Configuration ---
MODEL_NAME = 'llama3' 
ALERTS_FILE = 'snort_alerts.csv'
CURSOR_FILE = 'alert_cursor.txt'
SUGGESTED_RULES_FILE = 'suggested_rules.txt' # Define filename clearly

def engineer_features_for_single_alert(alert_info):
    """ Engineers features for a single alert row. """
    message = str(alert_info['message'])
    
    df = pd.DataFrame([{
        'message': message,
        'dest_port': int(alert_info['dest_port'])
    }])
    
    df['message_length'] = df['message'].str.len()
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit', 'scan']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    return df[['dest_port', 'message_length', 'special_char_count', 'keyword_count', 'message']]

def generate_snort_rule_prompt(alert_info):
    """ Constructs the prompt for Ollama. """
    src_ip = alert_info.get('source_ip', '$EXTERNAL_NET')
    dst_port = alert_info['dest_port']
    message = alert_info['message']
    
    payload_hint = "unknown"
    if "payload=" in str(message):
        try:
            payload_hint = str(message).split("payload=")[1].split(" ")[0]
        except: pass

    prompt = f"""
    You are a Snort 3 expert. Write a strict, production-ready Snort 3 rule to block the following threat.
    
    THREAT DETAILS:
    - Source IP: {src_ip}
    - Destination Port: {dst_port}
    - Full Alert Text: "{message}"
    - Suspected Payload: "{payload_hint}"

    STRICT REQUIREMENTS:
    1. HEADER: Use 'alert tcp any any -> $HOME_NET {dst_port}'. Do NOT hardcode the destination IP.
    2. CONTENT: Match ONLY the specific malicious part of the payload (e.g., '{payload_hint}'), not the entire request.
    3. METADATA:
       - flow:to_server, established
       - classtype:attempted-admin
       - sid:<generate_unique_id>
       - rev:1
    4. FORMAT: Output ONLY the raw rule line. No markdown, no explanations.

    OUTPUT:
    """
    return prompt

def get_new_alerts():
    """
    Reads only rows from the CSV that haven't been processed yet.
    Uses a cursor file to track position.
    """
    if not os.path.exists(ALERTS_FILE):
        print(f"Error: {ALERTS_FILE} not found.")
        return pd.DataFrame()

    # 1. Read the full CSV
    try:
        df = pd.read_csv(ALERTS_FILE)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return pd.DataFrame()
    
    current_row_count = len(df)

    # 2. Read the cursor (where did we stop last time?)
    last_processed_index = 0
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                last_processed_index = int(f.read().strip())
        except:
            last_processed_index = 0
    
    # 3. Filter for new rows
    if current_row_count > last_processed_index:
        new_data = df.iloc[last_processed_index:]
        print(f"[INFO] Found {len(new_data)} new alerts to process.")
        
        # Update cursor immediately to avoid re-processing if script crashes midway
        # (In a real production system, you'd update this AFTER processing)
        with open(CURSOR_FILE, 'w') as f:
            f.write(str(current_row_count))
            
        return new_data
    else:
        return pd.DataFrame() # Empty dataframe if no new data

def is_duplicate_rule(new_rule_text):
    """Checks if a rule with the same core logic already exists."""
    if not os.path.exists(SUGGESTED_RULES_FILE):
        return False
        
    try:
        with open(SUGGESTED_RULES_FILE, 'r') as f:
            existing_content = f.read()
            
        # Simple check: does the exact rule string exist?
        if new_rule_text.strip() in existing_content:
            return True
            
        # Advanced check: Extract the 'msg' part and see if we already have a rule for this msg
        # This prevents multiple rules for the exact same attack signature
        msg_match = re.search(r'msg:"([^"]+)"', new_rule_text)
        if msg_match:
            msg_content = msg_match.group(1)
            if msg_content in existing_content:
                return True
                
        return False
    except Exception as e:
        print(f"[WARN] Could not check for duplicates: {e}")
        return False

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load models
    try:
        classifier_pipeline = joblib.load('random_forest_pipeline.joblib')
        anomaly_pipeline = joblib.load('isolation_forest_pipeline.joblib')
    except FileNotFoundError as e:
        print(f"Error: Could not find model file: {e.filename}")
        sys.exit(1)

    # 2. Get Batch of New Alerts
    new_alerts_df = get_new_alerts()
    
    if new_alerts_df.empty:
        # Silent exit if nothing new (keeps logs clean in loop)
        sys.exit(0)

    # 3. Iterate through each new alert
    for index, row in new_alerts_df.iterrows():
        alert_msg = row['message']
        # Skip analyzing if the message is just "Generic" or "Benign" (optimization)
        if "Benign" in str(alert_msg): 
            continue

        print(f"\n--- Analyzing Alert #{index}: {str(alert_msg)[:50]}... ---")
        
        # Prepare data for model
        alert_info = {
            'message': row['message'],
            'source_ip': row.get('source_ip', '$EXTERNAL_NET'),
            'dest_port': row['dest_port'],
            'protocol': 'tcp'
        }

        feature_df = engineer_features_for_single_alert(alert_info)
        
        # Predict
        try:
            cls_pred = classifier_pipeline.predict(feature_df)[0]
            anom_pred = anomaly_pipeline.predict(feature_df)[0]
        except Exception as e:
            print(f"Model error on row {index}: {e}")
            continue

        # Logic
        is_malicious = (cls_pred == 1)
        is_anomaly = (anom_pred == -1)
        
        print(f"    Classifier: {'MALICIOUS' if is_malicious else 'Benign'}")
        print(f"    Anomaly:    {'ANOMALY' if is_anomaly else 'Normal'}")

        if is_malicious or is_anomaly:
            print("    [!] THREAT DETECTED. Generating Rule...")
            
            prompt = generate_snort_rule_prompt(alert_info)
            try:
                response = ollama.chat(
                    model=MODEL_NAME,
                    messages=[{'role': 'user', 'content': prompt}],
                    stream=False
                )
                
                rule = response['message']['content']
                rule = rule.replace('```', '').replace('snort', '').strip()
                rule = re.sub(r'src ip \S+', '', rule, flags=re.IGNORECASE)
                rule = re.sub(r'dst port \S+', '', rule, flags=re.IGNORECASE)
                rule = re.sub(r' +', ' ', rule)
                
                # --- De-Duplication Check ---
                if not is_duplicate_rule(rule):
                    with open(SUGGESTED_RULES_FILE, "a") as f: 
                        f.write(f"# Rule for Alert #{index}: {alert_msg}\n")
                        f.write(rule + "\n\n")
                    print("    [+] New rule appended to suggested_rules.txt")
                else:
                    print("    [i] Duplicate rule detected. Skipping write.")
                
            except Exception as e:
                print(f"    [-] Error calling Ollama: {e}")
        else:
            print("    [.] Alert classified as benign.")