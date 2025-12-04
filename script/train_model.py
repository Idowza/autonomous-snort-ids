import pandas as pd
import os
import glob
import numpy as np
import sys
import re
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
# Use absolute path to be safe
DATASET_ROOT = os.path.abspath('datasets')

# Default to 5% to prevent accidental OOM on first run
SAMPLE_RATE = 0.05

def get_user_sample_rate():
    """ Asks the user for a sample rate. """
    global SAMPLE_RATE
    print(f"\n--- Configuration ---")
    print(f"Current default loading sample rate is {SAMPLE_RATE * 100}%.")
    try:
        user_input = input("Enter desired loading sample rate (0.01 to 1.0) or press Enter to keep default: ").strip()
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

def find_column(df, candidates):
    """ Helper to find a column name case-insensitively, ignoring underscores/spaces. """
    cols_map = {c.strip().lower().replace('_', '').replace(' ', ''): c for c in df.columns}
    for cand in candidates:
        cand_norm = cand.strip().lower().replace('_', '').replace(' ', '')
        if cand_norm in cols_map:
            return cols_map[cand_norm]
    return None

# --- Loaders ---

def load_and_process_generic(folder_path, dataset_name="Unknown Dataset"):
    print(f"\n[+] Processing {dataset_name} from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    if not files:
        print(f"    [WARNING] No files found in {folder_path}")
        return pd.DataFrame()

    for f in files:
        try:
            # FIX: Explicitly handle UNSW-NB15 to force headerless reading
            if "UNSW-NB15" in dataset_name:
                unsw_cols = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label']
                # Read without header, assigning our own names
                df = pd.read_csv(f, header=None, names=unsw_cols, encoding='latin1', low_memory=False)
                
                # Filter down immediately to save RAM
                df = df[['dsport', 'attack_cat', 'Label']]
                port_col = 'dsport'
                label_col = 'Label'
                
            else:
                # Logic for standard datasets (CIC-IDS, etc) that usually HAVE headers
                header = pd.read_csv(f, nrows=0, encoding='latin1')
                port_col = find_column(header, ['Destination Port', 'Dst Port', 'dest_port', 'dsport', 'dp', 'Destination_Port'])
                label_col = find_column(header, ['Label', 'label', 'class', 'attack_cat'])
                
                if not port_col or not label_col:
                    print(f"    [SKIP] {os.path.basename(f)} missing columns. Found: {header.columns.tolist()}")
                    continue

                df = pd.read_csv(f, usecols=[port_col, label_col], encoding='latin1', low_memory=False)

            # Apply sampling
            if len(df) > 50000:
                df = df.sample(frac=SAMPLE_RATE, random_state=42)

            df.rename(columns={port_col: 'dest_port', label_col: 'raw_label'}, inplace=True)
            
            # Map specific dataset nuances to 'message'
            if "UNSW-NB15" in dataset_name and 'attack_cat' in df.columns:
                 df['message'] = df['attack_cat'].fillna('Unknown Attack')
            elif 'attack_cat' in df.columns:
                 df['message'] = df['attack_cat'].fillna('Unknown Attack')
            else:
                 df['message'] = df['raw_label'].astype(str)

            # Standardize Label (0 = Benign, 1 = Malicious)
            df['label'] = df['raw_label'].astype(str).apply(
                lambda x: 0 if any(benign in x.lower().strip() for benign in ['benign', 'normal', '0']) else 1
            )
            
            df = engineer_features(df)
            dfs.append(df)
            print(f"    Processed {os.path.basename(f)} ({len(df)} rows)")
            
        except Exception as e: 
            print(f"    [ERROR] processing {os.path.basename(f)}: {e}")
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
        print("    [WARNING] snort_alerts.csv not found.")
        return pd.DataFrame()

# --- Main Execution ---

if __name__ == "__main__":
    get_user_sample_rate()

    data_frames = []
    data_frames.append(load_local_snort())
    gc.collect()
    
    datasets_to_load = [
        ('cicids2017', 'CIC-IDS-2017'),
        ('cicids2018', 'CSE-CIC-IDS2018'),
        ('unsw_nb15', 'UNSW-NB15 (Original)'),
        ('cic_ddos_2019', 'CIC-DDoS-2019')
    ]

    for folder, name in datasets_to_load:
        path = os.path.join(DATASET_ROOT, folder)
        if os.path.exists(path):
            data_frames.append(load_and_process_generic(path, name))
            gc.collect()
        else:
            print(f"\n[INFO] Folder '{folder}' not found. Skipping {name}.")

    full_data = pd.concat(data_frames, ignore_index=True)
    
    if full_data.empty:
        print("\n[ERROR] No data loaded.")
        exit()

    print(f"\n[+] Total Processed Records: {len(full_data)}")
    print(f"    Raw Class Distribution: {full_data['label'].value_counts().to_dict()}")

    train_df = full_data

    # --- Runtime Memory Safety Check ---
    if len(train_df) > 5000000:
        print(f"\n[!] WARNING: Dataset size is {len(train_df)} records.")
        print("    Training Random Forest on >5M records may crash RAM (OOM Killed).")
        try:
            decision = input("    Do you want to auto-downsample to 5M records to be safe? (y/n): ").lower().strip()
            if decision == 'y':
                print("    [+] Downsampling to 5M records...")
                train_df = train_df.sample(n=5000000, random_state=42)
                print(f"    New Training Size: {len(train_df)}")
                gc.collect()
            else:
                print("    [!] Proceeding with full dataset. Good luck!")
        except: pass

    print("\n[+] Training Random Forest Classifier...")
    
    text_features = 'message'
    numeric_features = ['dest_port', 'message_length', 'special_char_count', 'keyword_count']
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            # REDUCED max_features from 5000 to 1000 to save RAM
            ('text', TfidfVectorizer(max_features=1000), text_features)
        ], remainder='passthrough')
    
    # REDUCED n_jobs from -1 to 2 to prevent thread memory overhead
    classifier = Pipeline(steps=[('preprocessor', preprocessor),
                                 ('clf', RandomForestClassifier(n_jobs=2, random_state=42))])
    
    X = train_df[numeric_features + [text_features]]
    y = train_df['label']
    
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

    print("\n[+] Training Isolation Forest Anomaly Detector...")
    # Train ONLY on benign data
    benign_training_data = train_df[train_df['label'] == 0]
    
    if not benign_training_data.empty:
        # Isolation Forest is extremely expensive. 
        # Even if user refused downsampling earlier, we cap IF training data for sanity.
        if len(benign_training_data) > 500000:
             print(f"    [INFO] Sub-sampling benign data to 500k for Isolation Forest training speed...")
             benign_training_data = benign_training_data.sample(n=500000, random_state=42)

        X_benign = benign_training_data[numeric_features + [text_features]]
        
        # REDUCED n_jobs here as well
        anomaly_detector = Pipeline(steps=[('preprocessor', preprocessor),
                                           ('clf', IsolationForest(n_jobs=2, random_state=42, contamination='auto'))])
        
        anomaly_detector.fit(X_benign)
        joblib.dump(anomaly_detector, 'isolation_forest_pipeline.joblib')
        print("    Anomaly Detector saved.")
    else:
        print("    [WARNING] No benign data found. Skipping Anomaly Detector training.")
    
    print("\n[SUCCESS] All models trained and saved.")