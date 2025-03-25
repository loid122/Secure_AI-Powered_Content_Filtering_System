# Secure_AI-Powered_Content_Filtering_System
This Assignment consists of 4 Tasks

# Task1 - URL Threat Analysis
This task consists of a single file:  

### **`Task1.py`**  
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
