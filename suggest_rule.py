import joblib
import ollama
import pandas as pd
import re
import sys
import os
import time
import random

# --- Configuration ---
MODEL_NAME = 'llama3.1:8b' 
ALERTS_FILE = 'snort_alerts.csv'
CURSOR_FILE = 'alert_cursor.txt'
SUGGESTED_RULES_FILE = 'suggested_rules.txt'

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
       - sid:1000005
       - rev:1
    4. FORMAT: Output ONLY the raw rule line. Do not write "Here is the rule". Start directly with "alert".

    CORRECT EXAMPLE:
    alert tcp any any -> $HOME_NET 80 (msg:"MALWARE-OTHER Log4j JNDI injection attempt"; flow:to_server,established; content:"${{jndi:ldap://"; classtype:attempted-admin; sid:1000005; rev:1;)

    OUTPUT:
    """
    return prompt

def get_new_alerts():
    """ Reads only rows from the CSV that haven't been processed yet. """
    if not os.path.exists(ALERTS_FILE):
        print(f"Error: {ALERTS_FILE} not found.")
        return pd.DataFrame()

    try:
        df = pd.read_csv(ALERTS_FILE)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return pd.DataFrame()
    
    current_row_count = len(df)

    last_processed_index = 0
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                last_processed_index = int(f.read().strip())
        except:
            last_processed_index = 0
    
    if current_row_count > last_processed_index:
        new_data = df.iloc[last_processed_index:]
        print(f"[INFO] Found {len(new_data)} new alerts to process.")
        
        with open(CURSOR_FILE, 'w') as f:
            f.write(str(current_row_count))
            
        return new_data
    else:
        return pd.DataFrame()

def is_duplicate_rule(new_rule_text):
    """Checks if a rule with the same core logic already exists."""
    if not os.path.exists(SUGGESTED_RULES_FILE):
        return False
    try:
        with open(SUGGESTED_RULES_FILE, 'r') as f:
            existing_content = f.read()
        if new_rule_text.strip() in existing_content:
            return True
        msg_match = re.search(r'msg:"([^"]+)"', new_rule_text)
        if msg_match:
            msg_content = msg_match.group(1)
            if msg_content in existing_content:
                return True
        return False
    except Exception as e:
        return False

def extract_valid_rule(text):
    """ 
    Simplified extractor that just looks for 'alert' and the ending ';)'
    without strict regex validation. 
    """
    # 1. Clean up common markdown
    text = text.replace("```snort", "").replace("```", "").strip()
    
    # 2. Find start of rule
    # We search for the word 'alert' followed by a space
    start_match = re.search(r'\balert\s', text)
    if not start_match:
        return None
    
    start_index = start_match.start()
    
    # 3. Find end of rule
    # We look for the last occurrence of ');' which ends standard Snort rules
    end_index = text.rfind(');')
    
    if end_index == -1 or end_index < start_index:
        # Fallback: try finding just a semicolon if ); is missing
        end_index = text.rfind(';')
        if end_index == -1: return None
        # If we found just a semicolon, we'll append the ) later manually if needed,
        # but usually a rule ends with );
        
    # 4. Extract the substring
    rule = text[start_index : end_index + 2] # include the );
    
    # 5. Flatten newlines
    rule = rule.replace('\n', ' ').replace('\r', '')
    
    # 6. Collapse multiple spaces
    rule = re.sub(r'\s+', ' ', rule)
    
    return rule.strip()

def generate_unique_sid():
    """Generates a time-based SID to ensure uniqueness."""
    return int(time.time()) + random.randint(1, 1000)

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
        sys.exit(0)

    # De-duplicate
    unique_alerts = new_alerts_df.drop_duplicates(subset=['message'])
    print(f"[INFO] Consolidated {len(new_alerts_df)} alerts into {len(unique_alerts)} unique threats.")

    # 3. Iterate through UNIQUE new alerts
    for index, row in unique_alerts.iterrows():
        alert_msg = row['message']
        if "Benign" in str(alert_msg) or "Generic" in str(alert_msg): 
            continue

        print(f"\n--- Analyzing Threat: {str(alert_msg)[:50]}... ---")
        
        alert_info = {
            'message': row['message'],
            'source_ip': row.get('source_ip', '$EXTERNAL_NET'),
            'dest_port': row['dest_port'],
            'protocol': 'tcp'
        }

        feature_df = engineer_features_for_single_alert(alert_info)
        
        try:
            cls_pred = classifier_pipeline.predict(feature_df)[0]
            anom_pred = anomaly_pipeline.predict(feature_df)[0]
        except Exception as e:
            print(f"Model error: {e}")
            continue

        is_malicious = (cls_pred == 1)
        is_anomaly = (anom_pred == -1)
        
        print(f"    Classifier: {'MALICIOUS' if is_malicious else 'Benign'}")
        print(f"    Anomaly:    {'ANOMALY' if is_anomaly else 'Normal'}")

        if is_malicious or is_anomaly:
            print("    [!] THREAT DETECTED. Asking AI for rule...")
            
            prompt = generate_snort_rule_prompt(alert_info)
            try:
                response = ollama.chat(
                    model=MODEL_NAME,
                    messages=[{'role': 'user', 'content': prompt}],
                    stream=False
                )
                
                raw_output = response['message']['content']
                
                # --- EXTRACT VALID RULE ---
                rule = extract_valid_rule(raw_output)
                
                if rule:
                    # --- CLEANUP STEPS ---
                    rule = re.sub(r'src ip \S+', '', rule, flags=re.IGNORECASE)
                    rule = re.sub(r'dst port \S+', '', rule, flags=re.IGNORECASE)
                    rule = rule.replace('fast_pattern;', '')
                    
                    new_sid = generate_unique_sid()
                    if "sid:" in rule:
                        rule = re.sub(r'sid:[^;]+;', f'sid:{new_sid};', rule)
                    else:
                        rule = rule.replace(')', f'; sid:{new_sid}; rev:1;)')

                    rule = re.sub(r'\s+', ' ', rule)

                    if not is_duplicate_rule(rule):
                        with open(SUGGESTED_RULES_FILE, "a") as f: 
                            f.write(f"# Rule for Alert: {alert_msg}\n")
                            f.write(rule + "\n\n")
                        print(f"    [+] Rule generated and saved (SID: {new_sid}).")
                    else:
                        print("    [i] Rule already exists in suggested_rules.txt. Skipping.")
                else:
                    print("    [!] AI response format issue (Skipping).")
                    print(f"    [DEBUG] Output: {raw_output[:100]}...") 

            except Exception as e:
                print(f"    [-] Error calling Ollama: {e}")
        else:
            print("    [.] Threat classified as benign/normal.")