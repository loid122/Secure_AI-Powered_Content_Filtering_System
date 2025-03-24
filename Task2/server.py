from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import base64

app = Flask(__name__)

# Read RSA Private Key
def read_private_pem_file(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# AES-GCM Decryption
def aes_gcm_decrypt(ciphertext, aes_key, nonce, tag):
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# RSA Decryption
def decrypt_data_with_rsa(encrypted_data, privatekey_file):
    private_key = read_private_pem_file(privatekey_file)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_data

# decrypt the data in a specific way
def decrypt_data(ciph):
    nonce = ciph[:12]  # Based on value sizes
    tag = ciph[12:28]  
    encrypted_aeskey = ciph[28:28 + 256]  # Since encrypted aeskey size is 256 bytes
    ciphertext = ciph[28 + 256:]  
    decrypted_aes_key = decrypt_data_with_rsa(encrypted_aeskey, 'private_key.pem')  # decrypt AES-key using rsa privatekey stored in server
    plaintext = aes_gcm_decrypt(ciphertext, decrypted_aes_key, nonce, tag)  # decrypt the remaining ciphertext using the decrypted AES-key
    return plaintext.decode()  


# Test endpoint, can be changed
@app.route('/receive', methods=['POST'])
def decrypt_data():
    try:
        data = request.json["data"]        # Decoding the way the client sent the data
        encrypted_bytes = base64.b64decode(data)  
        decrypted_data = decrypt_data(encrypted_bytes)  
        return jsonify({"decrypted_data": json.loads(decrypted_data)})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
