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
    
    THREAT: "{message}" (Port: {dst_port})
    PAYLOAD HINT: "{payload_hint}"

    REQUIREMENTS:
    1. Use header: alert tcp any any -> $HOME_NET {dst_port}
    2. Use content match for payload if available.
    3. Add metadata: flow:to_server,established; classtype:attempted-admin; sid:1000005; rev:1;
    4. OUTPUT ONLY THE RULE. NO TEXT. NO MARKDOWN.
    """
    return prompt

def get_new_alerts():
    if not os.path.exists(ALERTS_FILE): return pd.DataFrame()
    try:
        df = pd.read_csv(ALERTS_FILE)
    except: return pd.DataFrame()
    
    current_row_count = len(df)
    last_processed_index = 0
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                last_processed_index = int(f.read().strip())
        except: pass
    
    if current_row_count > last_processed_index:
        new_data = df.iloc[last_processed_index:]
        print(f"[INFO] Found {len(new_data)} new alerts to process.")
        with open(CURSOR_FILE, 'w') as f:
            f.write(str(current_row_count))
        return new_data
    return pd.DataFrame()

def is_duplicate_rule(new_rule_text):
    if not os.path.exists(SUGGESTED_RULES_FILE): return False
    try:
        with open(SUGGESTED_RULES_FILE, 'r') as f:
            content = f.read()
        if new_rule_text.strip() in content: return True
        msg_match = re.search(r'msg:"([^"]+)"', new_rule_text)
        if msg_match and msg_match.group(1) in content: return True
        return False
    except: return False

def extract_valid_rule(text):
    """ 
    Robust extractor that cleans Markdown and finds the rule 
    by looking for the start action and the final closing parenthesis.
    """
    # 1. Strip Markdown Code Blocks
    text = text.replace("```snort", "").replace("```", "").strip()
    
    # 2. Find the start of the rule (alert, log, drop, etc.)
    actions = ['alert', 'log', 'pass', 'drop', 'reject', 'sdrop']
    start_index = -1
    for action in actions:
        idx = text.find(action)
        if idx != -1:
            # We found an action. Ensure it's at the start or preceded by whitespace/newline
            if idx == 0 or text[idx-1].isspace():
                start_index = idx
                break # Found the primary action
    
    if start_index == -1: return None
    
    # 3. Find the end of the rule (the last closing parenthesis)
    end_index = text.rfind(')')
    if end_index == -1 or end_index < start_index: return None
    
    # 4. Slice the string to get just the rule
    rule = text[start_index : end_index + 1]
    
    # 5. Ensure it ends with a semicolon inside the parens
    # Some LLMs output '... rev:1)' without the semicolon
    if not rule.endswith(';)'):
        rule = rule[:-1] + ';)'
        
    # 6. Collapse newlines and extra spaces
    rule = " ".join(rule.split())
    
    return rule

def generate_unique_sid():
    return int(time.time()) + random.randint(1, 1000)

# --- Main Execution ---
if __name__ == "__main__":
    try:
        classifier = joblib.load('random_forest_pipeline.joblib')
        anomaly = joblib.load('isolation_forest_pipeline.joblib')
    except:
        print("Error: Models not found. Run train_model.py.")
        sys.exit(1)

    new_alerts_df = get_new_alerts()
    if new_alerts_df.empty: sys.exit(0)

    unique_alerts = new_alerts_df.drop_duplicates(subset=['message'])
    print(f"[INFO] Consolidated {len(new_alerts_df)} alerts into {len(unique_alerts)} unique threats.")

    for index, row in unique_alerts.iterrows():
        alert_msg = row['message']
        # Skip benign-looking messages to save time
        if "Benign" in str(alert_msg) or "Generic" in str(alert_msg): continue

        print(f"\n--- Analyzing Threat: {str(alert_msg)[:50]}... ---")
        print("    (Calculating threat score... this may take a moment)")
        
        alert_info = {
            'message': row['message'],
            'source_ip': row.get('source_ip', '$EXTERNAL_NET'),
            'dest_port': row['dest_port'],
            'protocol': 'tcp'
        }
        feature_df = engineer_features_for_single_alert(alert_info)
        
        try:
            cls_pred = classifier.predict(feature_df)[0]
            anom_pred = anomaly.predict(feature_df)[0]
        except: continue

        if cls_pred == 1 or anom_pred == -1:
            print("    [!] THREAT DETECTED. Generating Rule...")
            
            try:
                response = ollama.chat(
                    model=MODEL_NAME,
                    messages=[{'role': 'user', 'content': generate_snort_rule_prompt(alert_info)}],
                    stream=False
                )
                
                rule = extract_valid_rule(response['message']['content'])
                
                if rule:
                    # Cleanup hallucinations
                    rule = re.sub(r'src ip \S+', '', rule, flags=re.IGNORECASE)
                    rule = re.sub(r'dst port \S+', '', rule, flags=re.IGNORECASE)
                    rule = re.sub(r'\s+', ' ', rule)
                    
                    # Inject valid SID
                    new_sid = generate_unique_sid()
                    if "sid:" in rule:
                        rule = re.sub(r'sid:[^;]+;', f'sid:{new_sid};', rule)
                    else:
                        rule = rule.replace(')', f'; sid:{new_sid}; rev:1;)')

                    if not is_duplicate_rule(rule):
                        with open(SUGGESTED_RULES_FILE, "a") as f: 
                            f.write(f"# Rule for Alert: {alert_msg}\n")
                            f.write(rule + "\n\n")
                        print(f"    [+] Rule generated and saved (SID: {new_sid}).")
                    else:
                        print("    [i] Duplicate rule skipped.")
                else:
                    print("    [!] Could not extract a valid rule from AI response.")
            except Exception as e:
                print(f"    [-] Error: {e}")
        else:
            print("    [.] Classified as Benign.")