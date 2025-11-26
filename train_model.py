import pandas as pd
import os
import glob
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report
import joblib

# --- Configuration ---
# Use absolute path to be safe
DATASET_ROOT = os.path.abspath('datasets')

def engineer_features(df):
    """ Standardizes and engineers features for all datasets. """
    df['message'] = df['message'].astype(str).fillna('Unknown')
    
    # 1. Message Length
    df['message_length'] = df['message'].str.len()
    
    # 2. Special Character Count
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    
    # 3. Keyword Count
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit', 'scan']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    # 4. Clean Port
    df['dest_port'] = pd.to_numeric(df['dest_port'], errors='coerce').fillna(0).astype(int)
    
    return df[['message', 'dest_port', 'message_length', 'special_char_count', 'keyword_count', 'label']]

# --- Custom Loaders ---

def load_cicids2017(folder_path):
    print(f"\n[+] Loading CIC-IDS-2017 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    for f in files:
        try:
            # 2017 uses "Destination Port" and "Label"
            df = pd.read_csv(f, encoding='latin1', low_memory=False)
            
            # Normalize columns based on variations
            if 'Destination Port' in df.columns:
                df.rename(columns={'Destination Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            elif ' Destination Port' in df.columns: # Handle leading space
                 df.rename(columns={' Destination Port': 'dest_port', ' Label': 'raw_label'}, inplace=True)
            else:
                continue

            df['message'] = df['raw_label']
            df['label'] = df['raw_label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
            dfs.append(df[['dest_port', 'message', 'label']])
        except Exception: continue
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_cicids2018(folder_path):
    print(f"\n[+] Loading CSE-CIC-IDS2018 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, encoding='latin1', low_memory=False)
            
            # 2018 uses "Dst Port"
            if 'Dst Port' in df.columns:
                df.rename(columns={'Dst Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            else:
                continue
            
            df['message'] = df['raw_label']
            df['label'] = df['raw_label'].apply(lambda x: 0 if str(x).strip() == 'Benign' else 1)
            dfs.append(df[['dest_port', 'message', 'label']])
        except Exception: continue
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_unsw_nb15(folder_path):
    print(f"\n[+] Loading UNSW-NB15 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    # UNSW-NB15 raw CSVs have NO headers. We must provide them.
    # These are the standard column names for the 4 CSV files.
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
            # Read with header=None and names=unsw_columns
            df = pd.read_csv(f, header=None, names=unsw_columns, encoding='latin1', low_memory=False)
            
            df.rename(columns={'dsport': 'dest_port'}, inplace=True)
            
            df['message'] = df['attack_cat'].fillna('Benign Traffic')
            # Label column: 0 for normal, 1 for attack
            df['label'] = df['Label']
            
            dfs.append(df[['dest_port', 'message', 'label']])
        except Exception as e: 
            print(f"    Skipping {os.path.basename(f)}: {e}")
            continue
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_local_snort():
    print("\n[+] Loading Local Snort Logs...")
    try:
        df = pd.read_csv('snort_alerts.csv')
        df['label'] = 1 
        return df[['message', 'dest_port', 'label']]
    except FileNotFoundError:
        return pd.DataFrame()

# --- Main Execution ---

if __name__ == "__main__":
    
    # 1. Load All Data
    data_frames = []
    data_frames.append(load_local_snort())
    data_frames.append(load_cicids2017(os.path.join(DATASET_ROOT, 'cicids2017')))
    data_frames.append(load_cicids2018(os.path.join(DATASET_ROOT, 'cicids2018')))
    data_frames.append(load_unsw_nb15(os.path.join(DATASET_ROOT, 'unsw_nb15')))
    
    full_data = pd.concat(data_frames, ignore_index=True)
    
    if full_data.empty:
        print("\n[ERROR] No data loaded. Please check that your CSV files are in the 'datasets' subfolders.")
        exit()

    print(f"\n[+] Total Records Loaded: {len(full_data)}")
    print(f"    Class Distribution: {full_data['label'].value_counts().to_dict()}")

    # 2. Engineer Features
    print("[-] Engineering features...")
    full_data = engineer_features(full_data)
    
    # 3. Downsample
    if len(full_data) > 2000000:
        print(f"    Dataset is large ({len(full_data)}). Sampling 2M records for training...")
        train_df = full_data.sample(n=2000000, random_state=42)
    else:
        train_df = full_data

    # 4. Train Classifier
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
    
    X = train_df[numeric_features + [text_features]]
    y = train_df['label']
    
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    classifier.fit(X_train, y_train)
    
    print("    Classifier Evaluation:")
    preds = classifier.predict(X_test)
    
    # Dynamic Target Names Fix
    unique_labels = sorted(list(set(y_test) | set(preds)))
    target_names = []
    if 0 in unique_labels: target_names.append('Benign')
    if 1 in unique_labels: target_names.append('Malicious')

    print(classification_report(y_test, preds, target_names=target_names))
    
    joblib.dump(classifier, 'random_forest_pipeline.joblib')

    # 5. Train Anomaly Detector (Benign Data Only)
    print("\n[+] Training Isolation Forest Anomaly Detector...")
    benign_data = train_df[train_df['label'] == 0]
    
    if not benign_data.empty:
        if len(benign_data) > 500000:
            benign_sample = benign_data.sample(n=500000, random_state=42)
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