import pandas as pd
import os
import glob
import numpy as np
import sys
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report
import joblib
import gc

# --- Configuration ---
DATASET_ROOT = os.path.abspath('datasets')

# Default to 10% if not specified
SAMPLE_RATE = 0.1 

def get_user_sample_rate():
    """ Asks the user for a sample rate. """
    global SAMPLE_RATE
    print(f"\n--- Configuration ---")
    print(f"Current default sample rate is {SAMPLE_RATE * 100}%.")
    try:
        user_input = input("Enter desired sample rate (0.01 to 1.0) or press Enter to keep default: ").strip()
        if user_input:
            rate = float(user_input)
            if 0.0 < rate <= 1.0:
                SAMPLE_RATE = rate
                print(f"-> Sample rate set to {SAMPLE_RATE * 100}%")
            else:
                print("Invalid input. Using default.")
        else:
            print("Using default sample rate.")
    except ValueError:
        print("Invalid input. Using default.")

def engineer_features(df):
    """ Standardizes and engineers features. """
    df['message'] = df['message'].astype(str).fillna('Unknown')
    df['message_length'] = df['message'].str.len()
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit', 'scan']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    df['dest_port'] = pd.to_numeric(df['dest_port'], errors='coerce').fillna(0).astype(int)
    return df[['message', 'dest_port', 'message_length', 'special_char_count', 'keyword_count', 'label']]

# --- Loaders (Updated to use global SAMPLE_RATE) ---

def load_and_process_cicids2017(folder_path):
    print(f"\n[+] Processing CIC-IDS-2017 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, usecols=['Destination Port', 'Label'], encoding='latin1', low_memory=False)
            
            if len(df) > 50000:
                df = df.sample(frac=SAMPLE_RATE, random_state=42)

            df.rename(columns={'Destination Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            df['message'] = df['raw_label']
            df['label'] = df['raw_label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
            
            df = engineer_features(df)
            dfs.append(df)
            print(f"    Processed {os.path.basename(f)} ({len(df)} rows)")
        except Exception: continue
        finally: gc.collect()
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_and_process_cicids2018(folder_path):
    print(f"\n[+] Processing CSE-CIC-IDS2018 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, usecols=['Dst Port', 'Label'], encoding='latin1', low_memory=False)
            
            if len(df) > 50000:
                df = df.sample(frac=SAMPLE_RATE, random_state=42)

            df.rename(columns={'Dst Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            df['message'] = df['raw_label']
            df['label'] = df['raw_label'].apply(lambda x: 0 if str(x).strip() == 'Benign' else 1)
            
            df = engineer_features(df)
            dfs.append(df)
            print(f"    Processed {os.path.basename(f)} ({len(df)} rows)")
        except Exception: continue
        finally: gc.collect()
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_and_process_unsw_nb15(folder_path):
    print(f"\n[+] Processing UNSW-NB15 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    unsw_columns = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 
        'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 
        'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 
        'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 
        'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 
        'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 
        'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm', 
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
    ]

    for f in files:
        try:
            df = pd.read_csv(f, header=None, names=unsw_columns, encoding='latin1', low_memory=False)
            
            if len(df) > 50000:
                df = df.sample(frac=SAMPLE_RATE, random_state=42)
                
            df = df[['dsport', 'attack_cat', 'Label']].copy()
            df.rename(columns={'dsport': 'dest_port'}, inplace=True)
            df['message'] = df['attack_cat'].fillna('Benign Traffic')
            df['label'] = df['Label']
            
            df = engineer_features(df)
            dfs.append(df)
            print(f"    Processed {os.path.basename(f)} ({len(df)} rows)")
        except Exception as e: 
            print(f"    Skipping {os.path.basename(f)}: {e}")
            continue
        finally: gc.collect()
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_local_snort():
    print("\n[+] Loading Local Snort Logs...")
    try:
        df = pd.read_csv('snort_alerts.csv')
        df['label'] = 1 
        return engineer_features(df)
    except FileNotFoundError:
        return pd.DataFrame()

# --- Main Execution ---

if __name__ == "__main__":
    
    # 1. Get Sample Rate
    get_user_sample_rate()

    # 2. Load & Process Data (Incremental)
    data_frames = []
    
    data_frames.append(load_local_snort())
    gc.collect()
    
    data_frames.append(load_and_process_cicids2017(os.path.join(DATASET_ROOT, 'cicids2017')))
    gc.collect()

    data_frames.append(load_and_process_cicids2018(os.path.join(DATASET_ROOT, 'cicids2018')))
    gc.collect()

    data_frames.append(load_and_process_unsw_nb15(os.path.join(DATASET_ROOT, 'unsw_nb15')))
    gc.collect()
    
    full_data = pd.concat(data_frames, ignore_index=True)
    
    if full_data.empty:
        print("\n[ERROR] No data loaded.")
        exit()

    print(f"\n[+] Total Processed Records: {len(full_data)}")
    print(f"    Class Distribution: {full_data['label'].value_counts().to_dict()}")

    # 3. Train Classifier
    print("\n[+] Training Random Forest Classifier...")
    
    text_features = 'message'
    numeric_features = ['dest_port', 'message_length', 'special_char_count', 'keyword_count']
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('text', TfidfVectorizer(max_features=5000), text_features)
        ], remainder='passthrough')
    
    classifier = Pipeline(steps=[('preprocessor', preprocessor),
                                 ('clf', RandomForestClassifier(n_jobs=-1, random_state=42))])
    
    X = full_data[numeric_features + [text_features]]
    y = full_data['label']
    
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    except ValueError:
         X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    classifier.fit(X_train, y_train)
    
    preds = classifier.predict(X_test)
    unique_labels = sorted(list(set(y_test) | set(preds)))
    target_names = []
    if 0 in unique_labels: target_names.append('Benign')
    if 1 in unique_labels: target_names.append('Malicious')

    print(classification_report(y_test, preds, target_names=target_names))
    
    joblib.dump(classifier, 'random_forest_pipeline.joblib')

    # 4. Train Anomaly Detector
    print("\n[+] Training Isolation Forest Anomaly Detector...")
    benign_data = full_data[full_data['label'] == 0]
    
    if not benign_data.empty:
        # Use a manageable sample for Isolation Forest (e.g., 100k is usually enough to learn 'normal')
        if len(benign_data) > 100000:
            benign_sample = benign_data.sample(n=100000, random_state=42)
        else:
            benign_sample = benign_data
            
        X_benign = benign_sample[numeric_features + [text_features]]
        
        anomaly_detector = Pipeline(steps=[('preprocessor', preprocessor),
                                           ('clf', IsolationForest(n_jobs=-1, random_state=42, contamination='auto'))])
        
        anomaly_detector.fit(X_benign)
        joblib.dump(anomaly_detector, 'isolation_forest_pipeline.joblib')
        print("    Anomaly Detector saved.")
    else:
        print("    [WARNING] No benign data found. Skipping Anomaly Detector training.")
    
    print("\n[SUCCESS] All models trained and saved.")