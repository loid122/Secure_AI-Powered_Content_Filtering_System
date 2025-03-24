import requests
import time

url = 'http://127.0.0.1:5000/check'  # API ENDPOINT FOR SENDING POST REQUEST
payload = {'url': 'http://google.com'}   # THE URL THAT NEEDS TO BE CHECKED
 
try:
    res = requests.post(url, json=payload)
    
    # Keep checking until a valid JSON response is received
    while True:
        try:
            data = res.json() 
            if "risk_score" in data:
                print(f'"{payload["url"]}" has a risk score: {data["risk_score"]}')
                break
        except requests.exceptions.JSONDecodeError:
            print('Please wait, API is running...')
        
        time.sleep(2)  

except requests.exceptions.RequestException as e:
    print("Request failed:", e)
