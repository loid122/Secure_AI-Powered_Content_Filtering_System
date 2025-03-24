from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import requests
import json
import base64 

# Reading PEM files
def read_public_pem_file(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

# AES-GCM Encryption
def aesgcm_encrypt(plaintext):
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, aes_key, nonce, tag


# Encrypt AES key with RSA  for sending AES key to server to decrypt the data
def encrypt_data_with_rsa(data, publickey_file):
    public_key = read_public_pem_file(publickey_file)
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_data


# Encrypt User Data with AES-GCM-256 encryption
def encrypt_user_data(user_data):
    json_data = json.dumps(user_data)
    ciphertext, aes_key, nonce, tag = aesgcm_encrypt(json_data.encode())                       
    encrypted_aes_key = encrypt_data_with_rsa(aes_key, 'public_key.pem') 
  
    encrypted_payload = nonce + tag + encrypted_aes_key + ciphertext    # Making it a single value

    return base64.b64encode(encrypted_payload).decode()


# Sending Encrypted Data to Server
def send_req(data, url):
    enc_user_data = encrypt_user_data(data)
    response = requests.post(url, json={"data": enc_user_data}, verify=True)  # Verify = True checks if the server’s certificate is valid 
   #response = requests.post(url, json={"data": enc_user_data}, verify=certificate.pem)  We can also check for custom certificates if the server is using any
    print("Server Response:", response.text)


# User data for testing
user_data = {"user_id": "user123",
    "blocked_keywords": ["violence", "hate speech", "spam"],
    "blocked_websites": ["malicious.com", "ads.example.com"]}

# Tested with localhost as server , can be changed to server's url
send_req(user_data, "http://127.0.0.1:5000/receive")
