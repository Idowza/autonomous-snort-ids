import scapy.all as scapy
import joblib
import pandas as pd
import ollama
import re
import time
import random
import sys
import os

# --- Configuration ---
INTERFACE = "eth0"  # The interface to sniff on
MODEL_NAME = 'llama3.1:8b'
SUGGESTED_RULES_FILE = 'suggested_rules.txt'

# Load Models
try:
    classifier = joblib.load('random_forest_pipeline.joblib')
    anomaly_detector = joblib.load('isolation_forest_pipeline.joblib')
    print("[+] Models loaded successfully.")
except Exception as e:
    print(f"[!] Error loading models: {e}")
    sys.exit(1)

def extract_features_from_packet(packet):
    """
    Extracts the exact features your model expects from a raw Scapy packet.
    """
    if not packet.haslayer(scapy.IP):
        return None

    # Extract raw fields
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    
    if packet.haslayer(scapy.TCP):
        dest_port = packet[scapy.TCP].dport
        protocol = 'tcp'
        # Try to get payload
        try:
            payload = str(packet[scapy.TCP].payload)
        except:
            payload = ""
    elif packet.haslayer(scapy.UDP):
        dest_port = packet[scapy.UDP].dport
        protocol = 'udp'
        try:
            payload = str(packet[scapy.UDP].payload)
        except:
            payload = ""
    else:
        return None # Skip non-TCP/UDP for now

    # Engineer Features (Must match training EXACTLY)
    # Note: 'message' usually comes from Snort. Here we use the payload as the 'message'
    # to detect anomalies in the content itself.
    message = payload 
    
    df = pd.DataFrame([{
        'message': message,
        'dest_port': int(dest_port)
    }])
    
    df['message_length'] = len(message)
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit', 'scan']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    # Return features AND metadata for rule generation
    features = df[['dest_port', 'message_length', 'special_char_count', 'keyword_count', 'message']]
    metadata = {'src_ip': src_ip, 'dest_port': dest_port, 'message': message, 'protocol': protocol}
    
    return features, metadata

def generate_rule(meta):
    """Generates a Snort rule using Ollama."""
    print(f"    [!] AI Generating Rule for {meta['src_ip']} -> Port {meta['dest_port']}...")
    
    prompt = f"""
    Write a strict Snort 3 rule to block this malicious packet.
    
    DETAILS:
    - Source: {meta['src_ip']}
    - Dest Port: {meta['dest_port']}
    - Protocol: {meta['protocol']}
    - Payload Content: "{meta['message'][:100]}"
    
    REQUIREMENTS:
    1. Format: alert {meta['protocol']} any any -> $HOME_NET {meta['dest_port']}
    2. Metadata: flow:to_server,established; classtype:attempted-admin; sid:1000005; rev:1;
    3. Content: Match the payload content if it looks unique.
    4. OUTPUT ONLY THE RULE.
    """
    
    try:
        response = ollama.chat(model=MODEL_NAME, messages=[{'role': 'user', 'content': prompt}])
        rule = response['message']['content']
        # Basic cleanup
        rule = rule.replace('```', '').replace('snort', '').strip()
        return rule
    except:
        return None

def packet_callback(packet):
    """Called for every single packet sniffed."""
    result = extract_features_from_packet(packet)
    if not result:
        return

    features, meta = result
    
    # 1. AI Prediction
    try:
        # Is it known malicious?
        is_malicious = (classifier.predict(features)[0] == 1)
        # Is it an anomaly?
        is_anomaly = (anomaly_detector.predict(features)[0] == -1)
        
        if is_malicious or is_anomaly:
            reason = "KNOWN ATTACK" if is_malicious else "ZERO-DAY ANOMALY"
            print(f"\n[ALARM] {reason} detected from {meta['src_ip']}")
            print(f"        Payload: {meta['message'][:50]}...")
            
            # 2. Generate Rule
            rule = generate_rule(meta)
            if rule:
                print(f"        Proposed Rule: {rule}")
                with open(SUGGESTED_RULES_FILE, "a") as f:
                    f.write(f"# Auto-generated for {reason}\n{rule}\n\n")
                    
    except Exception as e:
        pass # Keep sniffing even if one packet fails

# --- Main Execution ---
if __name__ == "__main__":
    print(f"--- AI Packet Inspector Active on {INTERFACE} ---")
    print("Analyzing ALL traffic in real-time...")
    
    # Start Sniffing
    # store=0 prevents memory buildup
    scapy.sniff(iface=INTERFACE, prn=packet_callback, store=0)