# Secure_AI-Powered_Content_Filtering_System
This Assignment consists of 4 Tasks

Project
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
  - Decrypts the AES key using its **private RSA key**.  
  - Uses the decrypted AES key to **decrypt the ciphertext** and retrieve the original user data.  

This setup ensures **secure communication** between the client and the server using a combination of **AES-GCM** and **RSA encryption**.  

# Task3 - AI-Powered Threat Detection
This Task has 2 folders:
The **`BERT Model`** folder contains the following key files:  

- **`Test_Bertmodel.ipynb`** (Google Colab) – Notebook for testing the trained model.  
- **`Train_Bert_Model.ipynb`** (Google Colab) – Notebook for training the BERT model.  
- Additional files required for training and evaluation.  

### Model Details  

- Trains the **pretrained `bert-base-uncased` model** to classify URLs as **malicious (1) or safe (0)**.  
- Analyzes **domains, paths, query parameters, and IP patterns** to enhance classification accuracy.  
- Trained exclusively on **text-based data** for URL analysis.  
- Uses a combination of datasets:  
  - **Phishing URLs** from [urlhaus.abuse.ch](https://urlhaus.abuse.ch/)  
  - **Legitimate URLs**  
  - **Custom datasets** for robust model training.  

### Running the Model  

To use the trained model (`bert_model2.pth`):  

- Ensure it is placed in the correct directory.  
- In Google Colab, models should be stored under `/content/`.  
- Use a **GPU** while running the model, as it has been trained on GPU for optimized performance.  
