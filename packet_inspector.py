import scapy.all as scapy
import joblib
import pandas as pd
import ollama
import re
import time
import random
import sys
import os
import string
import ipaddress

# --- Configuration ---
INTERFACE = "enp5s0"
MODEL_NAME = 'llama3.1:8b'
SUGGESTED_RULES_FILE = 'suggested_rules.txt'

# 1. Define the Subnet to Ignore (Local LAN)
LOCAL_SUBNET = ipaddress.ip_network('192.168.1.0/24')

# 2. Define the Exception (Allow this specific IP from the ignored subnet)
ALLOWED_KALI_IP = '192.168.1.44'

# Ignore traffic TO these ports (Management)
IGNORED_PORTS = [22, 514]

# Load Models
try:
    classifier = joblib.load('random_forest_pipeline.joblib')
    anomaly_detector = joblib.load('isolation_forest_pipeline.joblib')
    print("[+] Models loaded successfully.")
except Exception as e:
    print(f"[!] Error loading models: {e}")
    sys.exit(1)

def is_printable(s):
    if not s: return False
    return all(c in string.printable for c in s)

def extract_features_from_packet(packet):
    if not packet.haslayer(scapy.IP):
        return None

    src_ip = packet[scapy.IP].src
    
    # --- FILTER LOGIC ---
    # If the packet is from our local subnet...
    if ipaddress.ip_address(src_ip) in LOCAL_SUBNET:
        # ...AND it is NOT our Kali machine...
        if src_ip != ALLOWED_KALI_IP:
            # ...then ignore it.
            return None
    # Otherwise (it's Kali OR it's from the Internet), proceed.
    # --------------------

    dest_port = 0
    protocol = 'other'
    payload_data = ""

    if packet.haslayer(scapy.TCP):
        dest_port = packet[scapy.TCP].dport
        protocol = 'tcp'
    elif packet.haslayer(scapy.UDP):
        dest_port = packet[scapy.UDP].dport
        protocol = 'udp'
    else:
        return None 

    if dest_port in IGNORED_PORTS:
        return None

    # Payload Extraction
    if packet.haslayer(scapy.Raw):
        raw_bytes = packet[scapy.Raw].load
        try:
            payload_data = raw_bytes.decode('utf-8')
        except:
            return None 
    
    if len(payload_data) < 5: return None
    if not is_printable(payload_data): return None

    # Feature Engineering
    df = pd.DataFrame([{
        'message': payload_data,
        'dest_port': int(dest_port)
    }])
    
    df['message_length'] = len(payload_data)
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit', 'scan']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    features = df[['dest_port', 'message_length', 'special_char_count', 'keyword_count', 'message']]
    metadata = {'src_ip': src_ip, 'dest_port': dest_port, 'message': payload_data, 'protocol': protocol}
    
    return features, metadata

def generate_rule(meta):
    print(f"    [!] AI Generating Rule for {meta['src_ip']} -> Port {meta['dest_port']}...")
    
    safe_payload = meta['message'][:100].replace('"', '\\"')

    prompt = f"""
    Write a strict Snort 3 rule to block this malicious packet.
    
    DETAILS:
    - Source: {meta['src_ip']}
    - Dest Port: {meta['dest_port']}
    - Protocol: {meta['protocol']}
    - Payload Content: "{safe_payload}"
    
    REQUIREMENTS:
    1. Format: alert {meta['protocol']} any any -> $HOME_NET {meta['dest_port']}
    2. Metadata: flow:to_server,established; classtype:attempted-admin; sid:<GENERATE_SID>; rev:1;
    3. Content: Match the payload content ONLY if it looks like a text-based attack.
    4. OUTPUT ONLY THE RULE.
    """
    
    try:
        response = ollama.chat(model=MODEL_NAME, messages=[{'role': 'user', 'content': prompt}])
        rule = response['message']['content']
        rule = rule.replace('```', '').replace('snort', '').strip()
        
        new_sid = int(time.time()) + random.randint(1, 1000)
        if "sid:" in rule:
            rule = re.sub(r'sid:[^;]+;', f'sid:{new_sid};', rule)
        else:
            rule = rule.replace(')', f'; sid:{new_sid}; rev:1;)')
            
        return rule
    except:
        return None

def is_duplicate_rule(new_rule_text):
    if not os.path.exists(SUGGESTED_RULES_FILE): return False
    try:
        with open(SUGGESTED_RULES_FILE, 'r') as f:
            existing_content = f.read()
        if new_rule_text.strip() in existing_content: return True
        return False
    except: return False

def packet_callback(packet):
    result = extract_features_from_packet(packet)
    if not result: return

    features, meta = result
    
    try:
        is_malicious = (classifier.predict(features)[0] == 1)
        
        if is_malicious:
            print(f"\n[ALARM] MALICIOUS PACKET from {meta['src_ip']}")
            print(f"        Payload: {meta['message'][:50]}...")
            
            rule = generate_rule(meta)
            if rule and not is_duplicate_rule(rule):
                print(f"        Proposed Rule: {rule}")
                with open(SUGGESTED_RULES_FILE, "a") as f:
                    f.write(f"# Auto-generated for Malicious Packet\n{rule}\n\n")
    except Exception: pass

if __name__ == "__main__":
    print(f"--- AI Packet Inspector Active on {INTERFACE} ---")
    print(f"--- Ignoring Local Subnet {LOCAL_SUBNET} EXCEPT {ALLOWED_KALI_IP} ---")
    print("Analyzing traffic...")
    scapy.sniff(iface=INTERFACE, prn=packet_callback, store=0)