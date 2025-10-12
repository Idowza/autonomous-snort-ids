# -*- coding: utf-8 -*-
"""
Snort Alert Classifier - Model Trainer

This script trains a machine learning model to classify Snort alerts as either
benign or malicious based on the preprocessed data.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import os

def train_and_evaluate_model(processed_csv_path):
    """
    Loads processed data, trains a Random Forest model, and evaluates its performance.

    Args:
        processed_csv_path (str): The path to the processed alerts CSV file.
    """
    try:
        # Load the preprocessed dataset
        print(f"Loading processed data from {processed_csv_path}...")
        df = pd.read_csv(processed_csv_path)

        # --- Prepare Data for Training ---
        # Separate the features (X) from the target label (y)
        X = df.drop('label', axis=1)
        y = df['label']
        print("Separated features (X) and labels (y).")

        # Split the data into training and testing sets
        # 80% of the data will be used for training, 20% for testing.
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"Split data into {len(X_train)} training samples and {len(X_test)} testing samples.")

        # --- Train the Model ---
        # Initialize the Random Forest Classifier
        # n_estimators is the number of trees in the forest.
        # random_state ensures reproducibility of results.
        model = RandomForestClassifier(n_estimators=100, random_state=42)

        print("\nTraining the Random Forest model...")
        # Fit the model to the training data
        model.fit(X_train, y_train)
        print("Model training complete.")

        # --- Evaluate the Model ---
        print("\nEvaluating model performance on the test set...")
        # Make predictions on the test data
        y_pred = model.predict(X_test)

        # Print a detailed classification report
        print("\nClassification Report:")
        # This report shows precision, recall, and f1-score for each class.
        print(classification_report(y_test, y_pred))

        # Print the confusion matrix
        print("Confusion Matrix:")
        # This shows how many predictions were correct vs. incorrect.
        print(confusion_matrix(y_test, y_pred))

    except FileNotFoundError:
        print(f"Error: Processed CSV file not found at '{processed_csv_path}'")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Define the input file path
    input_filename = 'processed_alerts.csv'
    
    # Assume the script is run from the same directory as the input CSV
    current_directory = os.getcwd()
    input_path = os.path.join(current_directory, input_filename)
    
    train_and_evaluate_model(input_path)

