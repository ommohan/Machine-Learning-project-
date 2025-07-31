import pandas as pd
import streamlit as st
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import GridSearchCV
import time


import os
st.write("📁 Current directory:", os.getcwd())
st.write("📂 Files available:", os.listdir())

# --- Streamlit Setup ---
st.set_page_config(page_title="URL Phishing Feature Extractor", layout="wide")
st.title("🚨 URL Phishing Feature Extractor")
st.write("This app loads URL data, extracts features, and displays the results.")

DATA_FILE = r"C:\\Users\\Om Mohan\\OneDrive\\Desktop\\project\\myenv\\malicious_phish.csv"

# --- Data Loading ---
@st.cache_data
def load_data(path):
    if not os.path.exists(path):
        st.error(f"Error: File not found at '{path}'")
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as e:
        st.error(f"Error reading CSV: {e}")
        return pd.DataFrame()

df = load_data(DATA_FILE)

# --- Feature Extraction ---
def extract_features(input_df):
    if 'url' not in input_df.columns:
        st.error("Missing 'url' column.")
        return input_df

    df_copy = input_df.copy()
    df_copy['url_length'] = df_copy['url'].apply(len)
    df_copy['domain'] = df_copy['url'].apply(lambda x: x.split('/')[0])
    df_copy['has_https'] = df_copy['url'].apply(lambda x: int('https' in x))
    df_copy['num_dots'] = df_copy['url'].apply(lambda x: x.count('.'))
    df_copy['has_symbol'] = df_copy['url'].apply(lambda x: int('@' in x))
    df_copy['has_ip'] = df_copy['domain'].apply(lambda x: int(not any(char.isalpha() for char in x) and any(char.isdigit() for char in x)))
    df_copy['num_slashes'] = df_copy['url'].apply(lambda x: x.count('/'))
    return df_copy

# --- Display ---
if not df.empty:
    st.subheader("🧾 Original Data Sample")
    st.dataframe(df.head().style.set_properties(**{
        'background-color': "#91856c",
        'color': '#333',
        'border': '1px solid #ccc'
    }))

    st.write(f"🔢 Shape: {df.shape[0]} rows × {df.shape[1]} columns")

    st.subheader("⚙️ Extracting Features...")
    processed_df = extract_features(df).head(5)

    st.subheader("🧪 Extracted Features")
    st.dataframe(processed_df.style.set_properties(**{
        'background-color': "#e6fffa",
        'color': '#111',
        'border': '1px solid #ddd'
    }).highlight_max(axis=0, color='#d2f0d2'))

    st.subheader("📊 Feature Statistics")
    styled_stats = processed_df.describe().style.background_gradient(cmap='BuGn').format(precision=2)
    st.dataframe(styled_stats)

else:
    st.warning("Please upload a valid file to continue.")

# --- TF-IDF Section ---
st.header("🧠 TF-IDF Vectorization")

vectorizer = TfidfVectorizer(max_features=500)
X = vectorizer.fit_transform(df['url'])
Y = df['type']

st.write("TF-IDF matrix shape:\n",X[:5])

# --- Train-Test Split ---
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=41)

# --- Decision Tree ---
dt_model = DecisionTreeClassifier(max_depth=10)
dt_model.fit(X_train, y_train)
dt_pred = dt_model.predict(X_test)

st.subheader("🌿 Decision Tree Results")
st.markdown(f"""
<div style="background-color:#f0fff0;padding:10px;border-radius:10px;">
<b>Accuracy:</b> {accuracy_score(y_test, dt_pred):.4f}
</div>
""", unsafe_allow_html=True)

st.code(classification_report(y_test, dt_pred), language="text")

# --- Random Forest ---


# --- Convert sparse TF-IDF matrix to DataFrame for sampling ---
X_train_dense = pd.DataFrame(X_train.toarray())
y_train_reset = y_train.reset_index(drop=True)

# --- Sample a subset for GridSearch (memory-safe) ---
sample_size = 5000  # reduce this if you hit memory issues
X_sample = X_train_dense.sample(n=sample_size, random_state=42)
y_sample = y_train_reset.loc[X_sample.index]

# --- Baseline Random Forest
rf = RandomForestClassifier(class_weight='balanced', random_state=42)

# --- Hyperparameter grid for tuning
param_grid = {
    'n_estimators': [100, 300],
    'max_depth': [None, 10, 30],
    'min_samples_split': [2, 5]
}

# --- Grid Search Setup
grid_search = GridSearchCV(estimator=rf,
                           param_grid=param_grid,
                           scoring='accuracy',
                           cv=3,
                           n_jobs=-1,
                           verbose=2)

# --- Fit Grid Search on Sampled Data
grid_search.fit(X_sample, y_sample)
best_rf = grid_search.best_estimator_

# --- Evaluate on full test set
rf_pred = best_rf.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
rf_report = classification_report(y_test, rf_pred)

# --- Show in Streamlit
st.subheader("🌲 Tuned Random Forest Results")
st.markdown(f"""
<div style="background-color:#fdf6f0;padding:10px;border-radius:10px;">
<b>Best Parameters:</b> {grid_search.best_params_}  
<br><b>Accuracy:</b> {rf_acc:.4f}
</div>
""", unsafe_allow_html=True)

st.code(rf_report, language="text")


# --- Sidebar Info ---
st.sidebar.header("About This App")
st.sidebar.info(
    "This app demonstrates URL feature extraction and classification "
    "for phishing detection using ML models. Styled with 💙 and Python."
)
st.sidebar.markdown("---")
st.sidebar.write("Developed by **Om** 🚀")


vectorizer = TfidfVectorizer(max_features=100)
rf_model = RandomForestClassifier(class_weight='balanced', random_state=42)

# train_save_model.py

# app.py
import streamlit as st
import pandas as pd
import pickle
import numpy as np

st.title("🔍 URL Malware Detection Dashboard")

# train_save_model.py
import pandas as pd
import pickle
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.ensemble import RandomForestClassifier

# Load labeled dataset
df = pd.read_csv(r"C:\\Users\\Om Mohan\\OneDrive\\Desktop\\project\\myenv\\malicious_phish.csv")

# Check column names
assert 'url' in df.columns and 'type' in df.columns, "Dataset must contain 'url' and 'label' columns"

# Feature extraction
vectorizer = HashingVectorizer(n_features=500, alternate_sign=False)
X_train = vectorizer.transform(df['url'])
y_train = df['type']

# Train model
rf_model = RandomForestClassifier(class_weight='balanced', random_state=42)
rf_model.fit(X_train, y_train)

# Save both model and vectorizer together
bundle = {'model': rf_model, 'vectorizer': vectorizer}
with open('malware_model_bundle.pkl', 'wb') as f:
    pickle.dump(bundle, f)

print("✅ Model and vectorizer saved as malware_model_bundle.pkl")



# Assuming rf_model and vectorizer are already trained
with open("malware_model_bundle.pkl", "wb") as f:
    pickle.dump({"model": rf_model, "vectorizer": vectorizer}, f)

print("🎉 Model saved successfully!")



# File uploader
uploaded_file = st.file_uploader("Drop a CSV or Excel file", type=['csv', 'xlsx'])

if uploaded_file:
    try:
        # Load file
        if uploaded_file.name.endswith('.csv'):
            file_data = pd.read_csv(uploaded_file)
        else:
            file_data = pd.read_excel(uploaded_file)

        st.success("✅ File successfully loaded")

        # Check for URL column
        if 'url' not in file_data.columns:
            st.error("❌ The uploaded file must contain a 'url' column.")
        else:
            st.write("📌 Sample URLs from file")
            st.dataframe(file_data['url'].head(5))

            # Load model and vectorizer
          

            try:
                with open('malware_model_bundle.pkl', 'rb') as f:
                    bundle = pickle.load(f)
                    rf_model = bundle['model']
                    vectorizer = bundle['vectorizer']
            except FileNotFoundError:
                    st.error("🚨 Model file missing. Please run the training script.")
                    st.stop()  # Optional: halt execution if model not found


            # Extract features
            url_vectors = vectorizer.transform(file_data['url'])

            # Predict
            predictions = rf_model.predict(url_vectors)
            file_data['predicted_label'] = predictions

            st.subheader("🧪 Prediction Results")
            st.dataframe(file_data[['url', 'predicted_label']].head(10))

            # Verdict check
            if np.any(predictions == 'malicious'):
                st.error("🚨 Warning: Malicious URLs detected.")
            else:
                st.success("🛡️ All URLs appear clean.")

    except Exception as e:
        st.error(f"⚠️ Something went wrong: {e}")
