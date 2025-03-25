import requests
import time
import urllib.parse
from flask import Flask, request

app = Flask(__name__)

# Initializing risk value globally
risk = 0

# Using Google Safe Browsing API 
def safebrowsing_check(url):
    global risk

    api_key = '~'   # GOOGLE SAFEBROWSING API-KEY TO BE USED HERE
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {'Content-Type': 'application/json'}
    parameter = {"key": api_key}

    payload = {
        "client": {
            "clientId": "secure_filter",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(api_url, json=payload, params=parameter, headers=headers)

    if res.json():
        risk += 5


# Using VirusTotal API
def virustotal_check(url):
    global risk

    vurl = "https://www.virustotal.com/api/v3/urls"
    virustotal_apikey = '~'    # VIRUSTOTAL API-KEY TO BE USED HERE

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": virustotal_apikey
    }

    payload = {'url': url}
    response = requests.post(vurl, headers=headers, data=payload)

    url2 = response.json()['data']['links']['self']

    headers2 = {
        "accept": "application/json",
        "x-apikey": virustotal_apikey
    }

    while True:
        resp = requests.get(url2, headers=headers2)
        status = resp.json()["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(5)

    stats = resp.json()['data']['attributes']['stats']
    harmless_val = stats['harmless']
    malicious_val = stats['malicious']
    suspicious_val = stats['suspicious']

    # Taking average to balance out false positives
    harm_avg = (malicious_val + suspicious_val) / (malicious_val + suspicious_val + harmless_val)

    if harm_avg < 0.1:
        risk += 1
    elif 0.1 <= harm_avg <= 0.2:
        risk += 2
    elif 0.2 < harm_avg <= 0.4:
        risk += 3
    elif 0.4 < harm_avg <= 0.6:
        risk += 4
    else:
        risk += 5


# Using IPQualityScore API
def ipquality_check(url):
    global risk
    ip_qual_api_key = "~"  # IPQUALITY API-KEY TO BE USED HERE
    encoded_url = urllib.parse.quote(url, safe="")  # URL needs to be encoded
    response = requests.get(f"https://www.ipqualityscore.com/api/json/url/{ip_qual_api_key}/{encoded_url}")

    try:
        data = response.json()
        risk_score = data.get("risk_score", 0)
        if risk_score <= 30:
            risk += 0
        elif risk_score <= 60:
            risk += 3  # Assumed due to threat level
        else:
            risk += 5  # Assumed due to threat level
    except requests.exceptions.JSONDecodeError:
        return "Error: API response is not in JSON format."


@app.route('/check', methods=['POST'])
def checker():
    global risk
    risk = 0  # Resetting risk for every request 

    data = request.get_json()
    url = data.get('url', '')   # Sanitizing input

    if not url:
        return {'error': 'No URL provided'}, 400

    safebrowsing_check(url)         # Running checks
    virustotal_check(url)
    ipquality_check(url)

    risk_score = risk / 15

    # Returning final risk rating of the url
    if risk_score < 0.3:
        return {'risk_score': 'Safe'}
    elif risk_score < 0.6:
        return {'risk_score': 'Warning'}
    else:
        return {'risk_score': 'Dangerous'}


if __name__ == '__main__':
    app.run(debug=True)
