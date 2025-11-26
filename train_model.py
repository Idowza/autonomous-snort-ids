import pandas as pd
import re
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
DATASET_ROOT = 'datasets' # Folder containing subfolders for each dataset

# --- Helper Functions for Feature Engineering ---

def engineer_features(df):
    """ Standardizes and engineers features for all datasets. """
    # Ensure we are working with strings
    df['message'] = df['message'].astype(str).fillna('Unknown')
    
    # Engineer Features
    df['message_length'] = df['message'].str.len()
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload', 'attack', 'exploit']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    # Ensure Port is Integer
    df['dest_port'] = pd.to_numeric(df['dest_port'], errors='coerce').fillna(0).astype(int)
    
    return df[['message', 'dest_port', 'message_length', 'special_char_count', 'keyword_count', 'label']]

# --- Dataset Specific Loaders ---

def load_cicids2017(folder_path):
    print(f"\n[+] Loading CIC-IDS-2017 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    # Standardizing Attack Labels to generic categories
    attack_map = {
        'BENIGN': 'Benign Traffic',
        'Bot': 'Botnet Activity',
        'DDoS': 'Denial of Service Attack',
        'DoS Hulk': 'Denial of Service Attack',
        'DoS GoldenEye': 'Denial of Service Attack',
        'DoS slowloris': 'Denial of Service Attack',
        'DoS Slowhttptest': 'Denial of Service Attack',
        'FTP-Patator': 'Brute Force FTP',
        'SSH-Patator': 'Brute Force SSH',
        'PortScan': 'Port Scan',
        'Heartbleed': 'Heartbleed Vulnerability',
        'Infiltration': 'Infiltration Attack',
        'Web Attack': 'Web Application Attack'
    }

    for f in files:
        try:
            # Read only necessary columns to save memory
            df = pd.read_csv(f, usecols=['Destination Port', 'Label'], encoding='latin1', low_memory=False)
            df.rename(columns={'Destination Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            
            # Map Labels
            df['message'] = df['raw_label'].map(attack_map).fillna('Generic Malicious Activity')
            df['label'] = df['raw_label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
            
            dfs.append(df)
        except ValueError: continue # Skip files without the right columns
            
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_cicids2018(folder_path):
    print(f"\n[+] Loading CSE-CIC-IDS2018 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    for f in files:
        try:
            # 2018 often uses 'Dst Port' instead of 'Destination Port'
            df = pd.read_csv(f, usecols=['Dst Port', 'Label'], encoding='latin1', low_memory=False)
            df.rename(columns={'Dst Port': 'dest_port', 'Label': 'raw_label'}, inplace=True)
            
            # 2018 labels are similar to 2017, reusing simple logic
            df['message'] = df['raw_label'].astype(str) # Use raw label as message for variety
            df['label'] = df['raw_label'].apply(lambda x: 0 if x == 'Benign' else 1)
            
            dfs.append(df)
        except ValueError: continue
            
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_unsw_nb15(folder_path):
    print(f"\n[+] Loading UNSW-NB15 from {folder_path}...")
    files = glob.glob(os.path.join(folder_path, '*.csv'))
    dfs = []
    
    for f in files:
        try:
            # UNSW usually uses 'dsport' and 'attack_cat' or 'Label'
            # We try to read typical UNSW columns
            df = pd.read_csv(f, encoding='latin1', low_memory=False)
            
            # Normalize Columns
            if 'dsport' in df.columns:
                df.rename(columns={'dsport': 'dest_port'}, inplace=True)
            elif 'dst_port' in df.columns: # Sometimes named differently
                df.rename(columns={'dst_port': 'dest_port'}, inplace=True)
            else:
                continue # Skip if no port info

            # Handle Labels
            if 'attack_cat' in df.columns:
                df['message'] = df['attack_cat'].fillna('Benign')
                df['label'] = df['message'].apply(lambda x: 0 if x.strip().lower() in ['benign', 'normal'] else 1)
            elif 'Label' in df.columns:
                df['label'] = df['Label']
                df['message'] = df['Label'].apply(lambda x: 'Benign Traffic' if x==0 else 'Malicious Activity')
            
            dfs.append(df[['dest_port', 'message', 'label']])
        except Exception as e: 
            print(f"Skipping {f}: {e}")
            continue
            
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def load_local_snort():
    print("\n[+] Loading Local Snort Logs...")
    try:
        df = pd.read_csv('snort_alerts.csv')
        # Local logs have 'message' and 'dest_port' already
        df['label'] = 1 # Assume all snort alerts are malicious/suspicious
        return df[['message', 'dest_port', 'label']]
    except FileNotFoundError:
        return pd.DataFrame()

# --- Main Execution ---

if __name__ == "__main__":
    
    # 1. Aggregate Data
    data_frames = []
    
    data_frames.append(load_local_snort())
    data_frames.append(load_cicids2017(os.path.join(DATASET_ROOT, 'cicids2017')))
    data_frames.append(load_cicids2018(os.path.join(DATASET_ROOT, 'cicids2018')))
    data_frames.append(load_unsw_nb15(os.path.join(DATASET_ROOT, 'unsw_nb15')))
    
    full_data = pd.concat(data_frames, ignore_index=True)
    
    if full_data.empty:
        print("Error: No data loaded. Check your folder structure.")
        exit()

    print(f"\n[+] Total Raw Records: {len(full_data)}")

    # 2. Feature Engineering
    print("[-] Engineering features...")
    full_data = engineer_features(full_data)
    
    # 3. Train Classifier (Random Forest)
    print("\n[+] Training Classifier (Random Forest)...")
    
    # Preprocessor setup
    text_features = 'message'
    numeric_features = ['dest_port', 'message_length', 'special_char_count', 'keyword_count']
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('text', TfidfVectorizer(max_features=1000), text_features) # Limit features to save RAM
        ], remainder='passthrough')
    
    classifier_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                          ('classifier', RandomForestClassifier(n_jobs=-1, random_state=42))])
    
    # Sample if data is too huge (optional, prevents crashing on limited RAM)
    if len(full_data) > 1000000:
        print("    (Downsampling training data to 1M records for performance)")
        train_sample = full_data.sample(n=1000000, random_state=42)
    else:
        train_sample = full_data

    X = train_sample[numeric_features + [text_features]]
    y = train_sample['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y)
    
    classifier_pipeline.fit(X_train, y_train)
    
    print("    Evaluating Classifier...")
    preds = classifier_pipeline.predict(X_test)
    print(classification_report(y_test, preds, target_names=['Benign', 'Malicious']))
    
    joblib.dump(classifier_pipeline, 'random_forest_pipeline.joblib')
    print("    Classifier saved.")

    # 4. Train Anomaly Detector (Isolation Forest)
    print("\n[+] Training Anomaly Detector (Isolation Forest)...")
    
    # Train ONLY on benign data
    benign_data = full_data[full_data['label'] == 0]
    
    if len(benign_data) > 500000:
        benign_sample = benign_data.sample(n=500000, random_state=42)
    else:
        benign_sample = benign_data
        
    X_benign = benign_sample[numeric_features + [text_features]]
    
    anomaly_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                       ('detector', IsolationForest(n_jobs=-1, random_state=42, contamination='auto'))])
    
    anomaly_pipeline.fit(X_benign)
    
    joblib.dump(anomaly_pipeline, 'isolation_forest_pipeline.joblib')
    print("    Anomaly Detector saved.")
    
    print("\n[SUCCESS] All models trained and updated.")