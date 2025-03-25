# Secure_AI-Powered_Content_Filtering_System
This Assignment consists of 4 Tasks

# Task1 - URL Threat Analysis
- This Python script analyzes URLs for potential threats like phishing, malware, or inappropriate content by leveraging multiple security APIs.
- It provides a comprehensive safety assessment by combining results from Google Safe Browsing, VirusTotal, and IPQualityScore APIs to average out risk values and decrease the number of false positives.
- It also blocks URLs with inappropriate keywords by checking from a list of blocked words.
- This script does not contain a valid API key (all keys have been replaced with ~), Please replace the placeholders with a valid API key to enable functionality.


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

- **`server.py`**  
  - Decrypts the AES key using its **private RSA key**.  
  - Uses the decrypted AES key to **decrypt the ciphertext** and retrieve the original user data.  

This setup ensures **secure communication** between the client and the server using a combination of **AES-GCM** and **RSA encryption**.  
