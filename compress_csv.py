import shutil
import os
import streamlit as st

# Replace with your CSV filename
input_file = "malicious_phish.csv"
output_file = "malicious_phish.csv.gz"

# Check if the file exists before compressing
if st.button("Compress CSV"):
    if os.path.exists("malicious_phish.csv"):
        with open("malicious_phish.csv", 'rb') as f_in, gzip.open("malicious_phish.csv.gz", 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        st.success("✅ File compressed and saved as malicious_phish.csv.gz")
    else:
        st.error("❌ File not found.")


if st.button("Compress Uploaded CSV"):
    with open(uploaded_file.name, 'rb') as f_in, gzip.open(uploaded_file.name + '.gz', 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    st.success("File compressed successfully!")
