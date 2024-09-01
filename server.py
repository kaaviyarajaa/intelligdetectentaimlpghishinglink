from flask import Flask, render_template, request
import re
import math
import time
import pandas as pd
import requests
import tldextract
import whois
from urllib.parse import urlparse
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

app = Flask(__name__)

# Your VirusTotal API key
API_KEY = 'your_api_key_here'

def get_virustotal_report(url):
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers)
    if response.status_code == 200:
        result = response.json()
        if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
            return 1  # Malicious
        return 0  # Safe
    return -1  # Error or not found

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['contains_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    suspicious_words = ['login', 'verify', 'secure', 'update', 'bank', 'account', 'signin', 'password']
    features['contains_suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0
    tld = tldextract.extract(url).suffix
    suspicious_tlds = ['ru', 'cn', 'tk', 'ml', 'ga']
    features['contains_suspicious_tld'] = 1 if tld in suspicious_tlds else 0
    features['https'] = 1 if urlparse(url).scheme == 'https' else 0
    domain = tldextract.extract(url).registered_domain
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age_days'] = (time.time() - creation_date.timestamp()) / (60 * 60 * 24) if creation_date else -1
    except Exception:
        features['domain_age_days'] = -1

    features['entropy'] = -sum(i * math.log(i) for i in [float(url.count(c)) / len(url) for c in set(url)])
    virustotal_result = get_virustotal_report(url)
    features['virustotal_flagged'] = 1 if virustotal_result == 1 else 0
    return features

def train_model(df):
    df_features = df['url'].apply(extract_features).apply(pd.Series)
    df = pd.concat([df, df_features], axis=1)
    X = df.drop(columns=['url', 'label'])
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = GradientBoostingClassifier()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(f'Accuracy: {accuracy_score(y_test, y_pred)}')
    return model

# Pre-trained model setup
sample_data = {
    'url': ['http://secure-login.yourbank.com/account/verify',
            'http://192.168.1.100/login',
            'https://www.google.com',
            'http://www.example.com/this/is/a/very/long/url/that/could/be/suspicious',
            'http://example.tk/login'],
    'label': [1, 1, 0, 1, 1]
}
df = pd.DataFrame(sample_data)
model = train_model(df)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    result = "🚨🚨 ALERT! 🚨🚨🚨\n❗❗❗ DANGER: This link might be a phishing link! ❗❗❗" if prediction == 1 else "This link appears to be safe."
    return render_template('index.html', url=url, result=result)

if __name__ == "__main__":
    app.run(debug=True)