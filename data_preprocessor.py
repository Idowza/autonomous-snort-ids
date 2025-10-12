# -*- coding: utf-8 -*-
"""
Snort Alert Data Preprocessor

This script takes the parsed CSV file from log_parser.py and prepares it for
machine learning by converting categorical text data into a numerical format
using one-hot encoding.
"""

import pandas as pd
import os

def preprocess_data(input_csv_path, output_csv_path):
    """
    Loads the parsed Snort alerts, adds labels, and performs one-hot encoding.

    Args:
        input_csv_path (str): The path to the input CSV file from the parser.
        output_csv_path (str): The path to save the final processed CSV file.
    """
    try:
        # Load the CSV file into a pandas DataFrame
        print(f"Loading data from {input_csv_path}...")
        df = pd.read_csv(input_csv_path)

        # --- Data Cleaning and Labeling ---
        # For this initial dataset, we assume all alerts are from our tests
        # and are therefore malicious. We will add a 'label' column and set it to 1.
        # In a real-world scenario, you would have a mix of benign (0) and malicious (1) traffic.
        df['label'] = 1
        print("Added 'label' column, marking all current alerts as malicious (1).")

        # --- Feature Engineering (One-Hot Encoding) ---
        # Select the columns that contain text data and need to be converted to numbers.
        categorical_features = ['alert_message', 'classification', 'protocol']
        
        print(f"Performing one-hot encoding on: {', '.join(categorical_features)}...")
        
        # Use pandas `get_dummies` to perform one-hot encoding.
        # This creates new columns for each category with a 1 or 0.
        df_encoded = pd.get_dummies(df, columns=categorical_features, prefix=categorical_features)
        
        # --- Finalizing the DataFrame ---
        # For simplicity, we can drop columns that are not useful for the initial model,
        # like timestamp and IP addresses (as we are focusing on alert types).
        # In a more advanced model, you might use these for time-series analysis or IP reputation.
        df_final = df_encoded.drop(columns=['timestamp', 'signature_id', 'source_ip', 'destination_ip'])

        # Reorder columns to have the 'label' at the end for clarity
        cols = [col for col in df_final.columns if col != 'label'] + ['label']
        df_final = df_final[cols]

        # Save the processed data to a new CSV file
        df_final.to_csv(output_csv_path, index=False)
        print(f"\nPreprocessing complete.")
        print(f"Processed data saved to: {output_csv_path}")
        print("\nColumns in the new dataset:")
        print(df_final.columns)

    except FileNotFoundError:
        print(f"Error: Input CSV file not found at '{input_csv_path}'")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Define the input and output file paths
    input_filename = 'snort_alerts.csv'
    output_filename = 'processed_alerts.csv'

    # Assume the script is run from the same directory as the input CSV
    current_directory = os.getcwd()
    input_path = os.path.join(current_directory, input_filename)
    output_path = os.path.join(current_directory, output_filename)

    preprocess_data(input_path, output_path)

