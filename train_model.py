import pandas as pd
import re
import os
import glob
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

def load_and_transform_cicids_from_folder(folder_path):
    """
    Loads all CSV files from a specified folder, transforms them,
    and concatenates them into a single DataFrame.
    """
    print(f"\nLoading and transforming all CSVs from '{folder_path}'...")
    all_csv_files = glob.glob(os.path.join(folder_path, '*.csv'))
    
    if not all_csv_files:
        print(f"Warning: No CSV files found in '{folder_path}'. Skipping this dataset.")
        return pd.DataFrame()

    list_of_dfs = []
    for filepath in all_csv_files:
        print(f"  - Processing {os.path.basename(filepath)}")
        try:
            # Added low_memory=False to suppress the DtypeWarning
            df = pd.read_csv(filepath, encoding='latin1', low_memory=False)
        except Exception as e:
            print(f"    - Could not read file {os.path.basename(filepath)} due to error: {e}")
            continue

        df.columns = df.columns.str.strip()
        # Ensure the required columns exist before trying to process
        if 'Destination Port' not in df.columns or 'Label' not in df.columns:
            print(f"    - Skipping file {os.path.basename(filepath)} because it's missing 'Destination Port' or 'Label' columns.")
            continue
            
        df = df[['Destination Port', 'Label']]
        df.rename(columns={'Destination Port': 'dest_port', 'Label': 'cicids_label'}, inplace=True)

        label_to_message = {
            'PortScan': 'Nmap Scan Attempt', 'SSH-Patator': 'SSH Brute-Force Attempt',
            'FTP-Patator': 'FTP Brute-Force Attempt', 'DoS Hulk': 'Denial of Service Attack',
            'DDoS': 'Denial of Service Attack'
        }
        df['message'] = df['cicids_label'].map(label_to_message)
        df['message'].fillna('Generic Attack Detected', inplace=True)
        df['label'] = df['cicids_label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        list_of_dfs.append(df[['message', 'dest_port', 'label']])

    if not list_of_dfs:
        return pd.DataFrame()
        
    combined_df = pd.concat(list_of_dfs, ignore_index=True)
    print(f"\nTransformed a total of {len(combined_df)} records from CIC-IDS-2017.")
    return combined_df

def label_snort_alerts(df):
    """ Creates a 'label' column for the Snort data. """
    malicious_keywords = ['Nmap', 'SSH Brute-Force', 'ICMP Ping Sweep']
    pattern = '|'.join(malicious_keywords)
    df['label'] = df['message'].str.contains(pattern, regex=True, na=False).astype(int)
    return df

def engineer_features(df):
    """ Creates new numerical features based on the alert message. """
    print("\nEngineering new features (length, special chars, keywords)...")
    
    df['message'] = df['message'].astype(str)
    
    df['message_length'] = df['message'].str.len()
    special_chars = r'[\$\{\}\(\)\'\/]'
    df['special_char_count'] = df['message'].str.count(special_chars)
    keywords = ['select', 'union', 'script', 'jndi', 'ldap', 'payload']
    keyword_pattern = '|'.join(keywords)
    df['keyword_count'] = df['message'].str.lower().str.count(keyword_pattern)
    
    return df

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load datasets
    try:
        snort_data = pd.read_csv('snort_alerts.csv')
        snort_data = label_snort_alerts(snort_data)
        print(f"Loaded {len(snort_data)} records from snort_alerts.csv")
        # **FIX**: Keep only the columns that both datasets will have
        snort_data = snort_data[['message', 'dest_port', 'label']]
    except FileNotFoundError:
        print("Warning: snort_alerts.csv not found. Proceeding with public data only.")
        snort_data = pd.DataFrame()

    cicids_data = load_and_transform_cicids_from_folder('cicids_data')
    
    # Now both dataframes have the same columns, so concatenation is safe
    combined_data = pd.concat([snort_data, cicids_data], ignore_index=True)

    if combined_data.empty:
        print("Error: No data available to train on. Please check your data files.")
        exit()

    # 2. Engineer Features
    combined_data = engineer_features(combined_data)
    combined_data['dest_port'] = pd.to_numeric(combined_data['dest_port'], errors='coerce')
    combined_data.dropna(inplace=True)
    combined_data['dest_port'] = combined_data['dest_port'].astype(int)
    
    print(f"\nTotal combined dataset size after cleaning: {len(combined_data)} records.")
    
    # 3. Prepare data for the model
    text_features = 'message'
    numeric_features = ['dest_port', 'message_length', 'special_char_count', 'keyword_count']

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('text', TfidfVectorizer(), text_features)
        ])

    model_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                     ('classifier', RandomForestClassifier(random_state=42))])

    X = combined_data[numeric_features + [text_features]]
    y = combined_data['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train the pipeline
    print("\nTraining the Random Forest model on the full combined dataset...")
    model_pipeline.fit(X_train, y_train)
    print("Model training complete.")
    print("-" * 40)

    # 5. Evaluate the model
    print("Evaluating model performance...")
    predictions = model_pipeline.predict(X_test)
    report = classification_report(y_test, predictions, target_names=['Benign', 'Malicious'])
    print(report)

    # 6. Save the final pipeline
    joblib.dump(model_pipeline, 'random_forest_pipeline.joblib')
    print("\nEntire model pipeline saved to 'random_forest_pipeline.joblib'")

