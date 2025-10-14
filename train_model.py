import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report

def label_alerts(df):
    """
    Creates a 'label' column based on the alert message.
    1 for malicious, 0 for benign.
    """
    # Define keywords that indicate a malicious alert in our test data
    malicious_keywords = ['Nmap', 'SSH Brute-Force', 'ICMP Ping Sweep']
    
    # Create a regex pattern to find any of the keywords
    pattern = '|'.join(malicious_keywords)
    
    # If the message contains a keyword, label it 1 (malicious), otherwise 0
    df['label'] = df['message'].str.contains(pattern, regex=True).astype(int)
    return df

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load the structured data
    try:
        data = pd.read_csv('snort_alerts.csv')
    except FileNotFoundError:
        print("Error: snort_alerts.csv not found. Make sure it's in the same directory.")
        exit()

    # 2. Label the data
    data = label_alerts(data)
    
    print("--- Data with Labels ---")
    print(data[['message', 'label']].head())
    print("-" * 26)

    # 3. Prepare data for the model
    # The 'message' column is our feature (X), and 'label' is our target (y)
    X = data['message']
    y = data['label']

    # Convert text data into numerical vectors
    vectorizer = TfidfVectorizer()
    X_vectorized = vectorizer.fit_transform(X)

    # Split data into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_vectorized, y, test_size=0.2, random_state=42
    )

    # 4. Train the Decision Tree model
    print("Training the Decision Tree model...")
    model = DecisionTreeClassifier(random_state=42)
    model.fit(X_train, y_train)
    print("Model training complete.")
    print("-" * 26)

    # 5. Evaluate the model
    print("Evaluating model performance...")
    predictions = model.predict(X_test)
    
    # Print the evaluation report (precision, recall, f1-score)
    report = classification_report(y_test, predictions, target_names=['Benign', 'Malicious'])
    print(report)
