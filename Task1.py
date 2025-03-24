import requests
import time
import urllib.parse
from urllib.parse import urlparse, parse_qs
import re

# URL TO BE TESTED 
url = input(" Enter the URL to be tested: ")

#initializing risk val
risk = 0

# Using Google Safe Browsing API 
def safebrowsing_check(url):
    global risk

    api_key = '~'   # GOOGLE SAFEBROWSING API-KEY TO BE USED HERE
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {'Content-Type': 'application/json'}
    parameter={"key": api_key}

    payload =   {
        "client": {
        "clientId":      "secure_filter",
        "clientVersion": "1.5.2"
        },
        "threatInfo": {
        "threatTypes":      ["MALWARE","UNWANTED_SOFTWARE" , "POTENTIALLY_HARMFUL_APPLICATION","SOCIAL_ENGINEERING"],
        "platformTypes":    ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [
            {"url": url }
        ]
        }
    }

    res = requests.post(api_url, json=payload,params= parameter , headers= headers)

    if res.json():
        threat = res.json()['matches'][0]['threatType']
        risk +=5        # Assumed on trustablity levels 
        return(f'{url} is likely a {threat} threat according to google')
        
    else:
        return(f'{url} is likely safe according to google')


# Using Virustotal API
def virustotal_check(url):
    global risk

    vurl = "https://www.virustotal.com/api/v3/urls"
    virustotal_apikey = '~'    # VIRUSTOTAL API-KEY TO BE USED HERE

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": virustotal_apikey
    }

    payload = { 'url' : url }

    response = requests.post(vurl, headers=headers,data= payload)


    url2 = response.json()['data']['links']['self']

    headers2 = {
                "accept": "application/json",
                "x-apikey": virustotal_apikey
                }

    while True : 
        resp = requests.get(url2, headers=headers2)
        status = resp.json()["data"]["attributes"]["status"]
        if status == "completed":
            break
        print('Url Scan running using virustotal API ....')
        print(status)
        time.sleep(5) 

    stats = resp.json()['data']['attributes']['stats']

    harmless_val = stats['harmless']
    malicious_val = stats['malicious']
    suspicious_val = stats['suspicious']

    # Taking average to balance out False positives
    harm_avg = (malicious_val + suspicious_val)/(malicious_val + suspicious_val + harmless_val)


    if harm_avg < 0.1:
        return f'{url} is likely safe according to VirusTotal'

    elif 0.1 <= harm_avg <= 0.2:  
        risk += 2
        return f'{url} is mildly suspicious according to VirusTotal'

    elif 0.2 < harm_avg <= 0.4: 
        risk += 3
        return f'{url} is moderately suspicious according to VirusTotal'

    elif 0.4 < harm_avg <= 0.6:  
        risk += 4
        return f'{url} is very suspicious according to VirusTotal'

    else:  
        risk += 5
        return f'{url} is likely harmful according to VirusTotal'

        


# Using Ipqualityscore API
def ipquality_check(url):
    global risk
    ip_qual_api_key = "~"      # IPQUALITY API-KEY TO BE USED HERE
    encoded_url = urllib.parse.quote(url, safe="")                  # url needs to be in url encoded form for this api
    response = requests.get(f"https://www.ipqualityscore.com/api/json/url/{ip_qual_api_key}/{encoded_url}")

    try:
        data = response.json()
        risk_score = data.get("risk_score")
        if risk_score <= 30:
            return(f"{url} is likely safe according to ipquality")
        elif risk_score <= 60:
            risk+=3   # assumed due to threat level
            return(f"{url} is likely suspicious according to ipquality")
            
        else:
            risk+=5    # assumed due to threat level
            return(f"{url} is likely harmful according to ipquality")
            

    except requests.exceptions.JSONDecodeError:
        return("Error: API response is not in JSON format.")



def final_check():
    # The Values can be finetuned 
    global risk
    if risk <5:
        return(f'{url} is likely safe Overall')
    elif risk < 13:
        return(f'{url} is likely suspicious Overall')
    else:
        return(f'{url} is likely harmful Overall')


def inappropriate_words_check(url):
    parsed_url = urlparse(url)
    url_text = parsed_url.netloc + parsed_url.path 
    query_param = parse_qs(parsed_url.query)
    query_text= " ".join([f"{key} {value}" for key, values in query_param.items() for value in values])

    full_url = f"{url_text} {query_text}"
    blocked_list= ["casino", "bet", "drugs", "murder", "hack", "illicit"]      # LIST OF BLOCKED KEYWORDS , CAN BE MODIFIED DEPENDING ON THE USE CASE
    for word in blocked_list:
        if re.search(rf"\b{word}\b", full_url, re.IGNORECASE):  
            return (f'URL IS BLOCKED DUE TO "{word}" KEYWORD BEING IN BLOCKED LIST')

    return "URL IS CLEAN"
 


print(safebrowsing_check(url))
print(virustotal_check(url))
print(ipquality_check(url))
print(final_check())
print(inappropriate_words_check(url))
