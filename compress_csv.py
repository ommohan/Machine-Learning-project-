import pandas as pd
import gzip
import os

# Set path to your compressed CSV
file_path = "malicious_phish.csv.gz"

# Check if file exists before attempting to load
if os.path.exists(file_path):
    with gzip.open(file_path, 'rt') as f:
        df = pd.read_csv(f)
    print("✅ CSV loaded successfully!")
    print(f"📊 Data shape: {df.shape}")
    print(df.head())  # Display first few rows
else:
    print(f"❌ File not found: {file_path}")
