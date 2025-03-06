from flask import Flask, request, jsonify
import pandas as pd
import joblib
import re
import whois
from urllib.parse import urlparse
import logging

# Load the trained model
model = joblib.load('best_model.pkl')

# Configure Logging
logging.basicConfig(
    filename='app_logs.txt',  
    level=logging.INFO,       
    format='%(asctime)s - %(levelname)s - %(message)s',  
    datefmt='%Y-%m-%d %H:%M:%S'
)

log = logging.getLogger('werkzeug')
log.disabled = True  # Disable Flask's default logging

# ----------------------------
# Feature Extraction Functions
# ----------------------------

def use_of_ip(url):
    ipv4_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    ipv6_pattern = r'([a-fA-F0-9:]+:+)+[a-fA-F0-9]+'
    return 1 if re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url) else 0

def abnormal_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return 1
        return 0 if hostname in url and url.index(hostname) == url.find(parsed_url.netloc) else 1
    except:
        return 1

def count_character(url, char):
    return url.count(char)

def domain_length(url):
    return len(urlparse(url).netloc)

def short_url(url):
    return 1 if len(url) < 20 else 0

def no_of_embed(url):
    return urlparse(url).path.count('//')

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def suspicious_words(url):
    return 1 if re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url) else 0

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def legitimate_TLD(url):
    pass  # This function is incomplete in the original code

def extract_features(df):
    df['use_of_ip'] = df['url'].apply(use_of_ip)
    df['abnormal_url'] = df['url'].apply(abnormal_url)
    df['count.'] = df['url'].apply(lambda x: count_character(x, '.'))
    df['count-www'] = df['url'].apply(lambda x: count_character(x, 'www'))
    df['count@'] = df['url'].apply(lambda x: count_character(x, '@'))
    df['count-dir'] = df['url'].apply(lambda x: count_character(x, '/'))
    df['short_url'] = df['url'].apply(short_url)
    df['url_length'] = df['url'].apply(len)
    df['hostname_length'] = df['url'].apply(domain_length)
    df['count-'] = df['url'].apply(lambda x: count_character(x, '-'))
    df['count='] = df['url'].apply(lambda x: count_character(x, '='))
    df['count?'] = df['url'].apply(lambda x: count_character(x, '?'))
    df['count%'] = df['url'].apply(lambda x: count_character(x, '%'))
    df['count-digits'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))
    df['count-letters'] = df['url'].apply(lambda x: sum(c.isalpha() for c in x))
    df['count_embed_domian'] = df['url'].apply(no_of_embed)
    df['count-https'] = df['url'].apply(count_https)
    df['count-http'] = df['url'].apply(count_http)
    df['sus_url'] = df['url'].apply(suspicious_words)
    df['fd_length'] = df['url'].apply(fd_length)
    df['legitimate_TLD'] = df['url'].apply(legitimate_TLD)

    return df

# ----------------------------
# WHOIS Lookup Function
# ----------------------------

def get_whois_info(url):
    """Fetch WHOIS information for a given URL."""
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        def get_first_value(value):
            """Extracts the first value if it's a list, otherwise returns as is."""
            return value[0] if isinstance(value, list) else value

        return {
            "domain_name": get_first_value(w.domain_name),
            "registrar": w.registrar if w.registrar else "Unknown",
            "whois_server": w.whois_server if w.whois_server else "Unknown",
            "name_servers": w.name_servers if w.name_servers else "Unknown",
            "creation_date": str(get_first_value(w.creation_date)) if w.creation_date else "Unknown",
            "expiration_date": str(get_first_value(w.expiration_date)) if w.expiration_date else "Unknown",
            "updated_date": str(get_first_value(w.updated_date)) if w.updated_date else "Unknown",
            "registrant_country": w.country if w.country else "Unknown",
            "registrant_organization": w.org if hasattr(w, 'org') else "Unknown"
        }

    except Exception as e:
        print(f"WHOIS lookup failed for {url}: {e}")
        return {
            "domain_name": "Unknown",
            "registrar": "Unknown",
            "whois_server": "Unknown",
            "name_servers": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "registrant_country": "Unknown",
            "registrant_organization": "Unknown"
        }

# ----------------------------
# Flask App Initialization
# ----------------------------

app = Flask(__name__)

@app.route('/')
def home():
    return "URL Classifier API is running!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get URL from the request
        data = request.json
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Wrap URL in a DataFrame
        new_data = pd.DataFrame({'url': [url]})
        
        # Extract features (for model prediction)
        features = extract_features(new_data)
        
        # Ensure correct feature order
        feature_order = ['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
                         'count-dir', 'count_embed_domian', 'short_url', 'count-https',
                         'count-http', 'count%', 'count?', 'count-', 'count=',
                         'url_length', 'hostname_length', 'sus_url', 'fd_length',
                         'count-digits', 'count-letters','legitimate_TLD']
        
        X_new = features[feature_order]
        
        # Make prediction
        prediction = model.predict(X_new)[0]
        label_mapping = {0: 'Benign', 1: 'Defacement', 2: 'Malware', 3: 'Phishing'}
        result = label_mapping.get(prediction, 'Unknown')

        # Get WHOIS info (Not used for prediction, just included in response)
        whois_info = get_whois_info(url)

        logging.info(f"{url} - {result}")             

        return jsonify({
            'url': url,
            'prediction': result,
            'whois': whois_info
        })
    
    except KeyError as e:
        print("Feature mismatch error:", e)
        return jsonify({'error': f'Feature mismatch: {e}'}), 500
    
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

# ----------------------------
# Main Function to Run Server
# ----------------------------
if __name__ == '__main__':
    app.run(debug=True)
