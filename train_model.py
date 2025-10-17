import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

def load_and_transform_cicids(filepath):
    """
    Loads and transforms the CIC-IDS-2017 dataset to a format
    compatible with our Snort alert data.
    """
    print(f"\nLoading and transforming {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found. Skipping this dataset.")
        return pd.DataFrame()

    # Column names in CIC-IDS-2017 can have leading/trailing spaces
    df.columns = df.columns.str.strip()

    # Select relevant columns
    df = df[['Destination Port', 'Label']]
    
    # Rename columns to match our format
    df.rename(columns={'Destination Port': 'dest_port', 'Label': 'cicids_label'}, inplace=True)

    # Create a 'message' column by mapping known attack labels
    label_to_message = {
        'PortScan': 'Nmap Scan Attempt',
        'SSH-Patator': 'SSH Brute-Force Attempt',
        'FTP-Patator': 'FTP Brute-Force Attempt',
        'DoS Hulk': 'Denial of Service Attack',
        'DDoS': 'Denial of Service Attack'
    }
    
    df['message'] = df['cicids_label'].map(label_to_message)
    # Fill in a generic message for other attacks
    df['message'].fillna('Generic Attack Detected', inplace=True)
    
    # Create the binary 'label' column (0 for BENIGN, 1 for any attack)
    df['label'] = df['cicids_label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    print(f"Transformed {len(df)} records from CIC-IDS-2017.")
    return df[['message', 'dest_port', 'label']]


def label_snort_alerts(df):
    """
    Creates a 'label' column for the Snort data.
    """
    malicious_keywords = ['Nmap', 'SSH Brute-Force', 'ICMP Ping Sweep']
    pattern = '|'.join(malicious_keywords)
    df['label'] = df['message'].str.contains(pattern, regex=True).astype(int)
    return df

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load your original Snort data
    try:
        snort_data = pd.read_csv('snort_alerts.csv')
        snort_data = label_snort_alerts(snort_data)
        print(f"Loaded {len(snort_data)} records from snort_alerts.csv")
    except FileNotFoundError:
        print("Warning: snort_alerts.csv not found. Starting with an empty dataframe.")
        snort_data = pd.DataFrame()

    # 2. Load and transform the CIC-IDS-2017 data
    cicids_data = load_and_transform_cicids('cicids2017.csv')

    # 3. Combine the two datasets
    combined_data = pd.concat([snort_data, cicids_data], ignore_index=True)
    if combined_data.empty:
        print("Error: No data to train on. Please provide at least one CSV file.")
        exit()
        
    print(f"\nTotal combined dataset size: {len(combined_data)} records.")
    
    # Clean up data - ensure dest_port is numeric
    combined_data['dest_port'] = pd.to_numeric(combined_data['dest_port'], errors='coerce')
    combined_data.dropna(subset=['dest_port'], inplace=True)
    combined_data['dest_port'] = combined_data['dest_port'].astype(int)

    print("\n--- Combined Data Sample (First 5 Rows) ---")
    print(combined_data[['message', 'dest_port', 'label']].head())
    print("-" * 40)

    # 4. Prepare data for the model
    text_features = 'message'
    numeric_features = ['dest_port']

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('text', TfidfVectorizer(), text_features)
        ])

    model_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                     ('classifier', RandomForestClassifier(random_state=42))])

    X = combined_data[['message', 'dest_port']]
    y = combined_data['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y # stratify is good for imbalanced datasets
    )

    # 5. Train the full pipeline
    print("Training the Random Forest model on the combined dataset...")
    model_pipeline.fit(X_train, y_train)
    print("Model training complete.")
    print("-" * 40)

    # 6. Evaluate the model
    print("Evaluating model performance...")
    predictions = model_pipeline.predict(X_test)
    
    report = classification_report(y_test, predictions, target_names=['Benign', 'Malicious'])
    print(report)

    # 7. Save the entire pipeline to a file
    joblib.dump(model_pipeline, 'random_forest_pipeline.joblib')
    print("Entire model pipeline saved to 'random_forest_pipeline.joblib'")


