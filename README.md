# Secure_AI-Powered_Content_Filtering_System
This Assignment consists of 4 Tasks

To get the contents of this repository, please run the following commands
```bash
git clone https://github.com/loid122/Secure_AI-Powered_Content_Filtering_System.git
git pull
git lfs pull
```
Tasks
│   .gitattributes
│   bert_model2.pth
│   LICENSE
│   README.md
│
├───Task1
│       Task1.py
│
├───Task2
│       client.py
│       server.py
│
├───Task3
│   ├───Bert Model
│   │       data.txt
│   │       legitimate-urls.csv
│   │       phishing-urls.csv
│   │       Test_Bertmodel.ipynb
│   │       Train_Bert_Model.ipynb
│   │       urlhaus.abuse.ch.txt
│   │
│   └───Random Forest Model
│           .gitattributes
│           legitimate-urls.csv
│           phishing-urls.csv
│           PhiUSIIL_Phishing_URL_Dataset.csv
│           randforest.ipynb
│           urlhaus.abuse.ch.txt
│
└───Task4
    └───API
            client.py
            Flaskapp.py




# Task1 - URL Threat Analysis
This task consists of a single file:  

**`Task1.py`**  
- This Python script uses multiple security APIs to analyze URLs for potential threats, including phishing, malware, and inappropriate content.  
- Aggregates results from **Google Safe Browsing, VirusTotal, and IPQualityScore** to provide a comprehensive risk assessment and minimize false positives.  
- Blocks URLs containing inappropriate keywords by cross-referencing a predefined list of restricted terms.  
- **Note:** This script does not contain a valid API key (all keys have been replaced with `~`). Replace the placeholders with a valid API key to enable functionality.  


# Task2 - Data Security & Encryption
This task has two files:  

- **`client.py`**  
- **`server.py`**  

## Encryption Details  

- **`client.py`**  
  - Utilizes **AES-GCM 256** encryption to securely encrypt user data.  
  - Uses an **AES key** for encryption.  
  - To enhance security, the AES key is encrypted with the **server’s public RSA key**.  
  - This ensures that only the server can decrypt the AES key using its **private RSA key**.  
  - The client only needs the **server’s public key** for secure encryption.
  - The client sends the  data using a post request to one of the server's endpoints (in this case) after verifying the server's certificate 

- **`server.py`**
  - Uses Flask as backend (in this case) to accept the requests sent by the client
  - Decrypts the AES key using its **private RSA key**.  
  - Uses the decrypted AES key to **decrypt the ciphertext** and retrieve the original user data.  

This setup ensures **secure communication** between the client and the server using a combination of **AES-GCM** and **RSA encryption**.  

# Task3 - AI-Powered Threat Detection
## BERT Model
The **`BERT Model`** folder contains the following key files:  

- **`Test_Bertmodel.ipynb`** (Google Colab) – Notebook for testing the trained model.  
- **`Train_Bert_Model.ipynb`** (Google Colab) – Notebook for training the BERT model.  
- Additional files required for training and evaluation.  

#### Model Details  

- Trains the **pretrained `bert-base-uncased` model** to classify URLs as **malicious (1) or safe (0)**.  
- Analyzes **domains, paths, query parameters, and IP patterns** to enhance classification accuracy.  
- Trained exclusively on **text-based data** for URL analysis.  
- Uses a combination of datasets:  
  - **Phishing URLs** from [urlhaus.abuse.ch](https://urlhaus.abuse.ch/)  
  - **Legitimate URLs**  
  - **Custom datasets** for robust model training.  

#### Testing the Model  

The **`Test_Bertmodel.ipynb`** notebook uses a Flask API to serve the BERT model for testing and inference.  
- **Model Loading & Testing** – It loads the model (bert_model2.pth), gets post requests, analyzes the URLs, and returns predictions.
- We can use Python's requests module to send the URL in JSON format to check if it is malicious or not
- Ensure it is placed in the correct directory.  
- In Google Colab, models should be stored under `/content/`.  
- Use a **GPU** while running the model, as it has been trained on GPU for optimized performance.
- It showed an accuracy of **90.25%**
## Random Forest Model  

The **`Random Forest Model`** folder contains the **`randforest.ipynb`** notebook along with datasets.  

- **Feature Engineering** – The model is trained on numerical data (integers and floats) derived from various URL properties, such as path length, domain length, number of special characters, etc.  
- **Feature Importance Analysis** – After training, the model generates an importance table highlighting the most significant features for classifying URLs as malicious or legitimate.  
- Showed an accuracy of **0.9956** during training


# Task4 - API & Safe Browsing
## API 
- **Backend Framework** – The API is built using Flask to provide a lightweight and efficient backend for URL risk assessment.  
- **Multi-Source Risk Evaluation** – It integrates multiple security services, including Google Safe Browsing, VirusTotal, and IPQualityScore, to provide a comprehensive risk assessment.  
- **Risk Scoring Mechanism** – The system assigns risk scores based on threat reports from multiple sources and classifies URLs as Safe, Warning, or Dangerous.  
- **Error Handling & API Management** – Implements robust error handling to ensure smooth API responses and manage failed requests.  
- **API Endpoint** – Provides a POST endpoint (`/check`) that accepts a URL and returns its risk classification.
- **Client-Server Interaction** – The `client.py` script sends a URL to the Flask-based API for risk assessment. It waits for the API to process the request and continuously checks for a valid JSON response before displaying the final risk classification sent by the api.

## CLI Tool
- A command-line tool to block or unblock unsafe URLs.  
- **Hosts File Modification** – Edits the system's hosts file to redirect unsafe URLs to `127.0.0.1`.  
- **Automatic URL Handling** – Supports both `www.` and non-`www.` versions of a domain.  
- **Administrator Privileges Required** – Needs elevated permissions to modify system files.  
- **Error Handling** – Detects permission issues and prevents duplicate entries.  
- **Cross-Platform Support** – Works on both Windows and Linux.  

