# client.py
import base64
import socket
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


with open('C:\\ssl\\server.crt', "rb") as cert_file:
    cert = x509.load_pem_x509_certificate(cert_file.read())
with open('C:\\ssl\\server.key', "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)


key = cert.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)


hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=None,
)

derived_key = hkdf.derive(key)
cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12333))


message = "Never underestimate a developer with a deadline."
encrypted_message = cipher_suite.encrypt(message.encode())
print(f"Encrypted message: {encrypted_message}")
client_socket.send(encrypted_message)


encrypted_response = client_socket.recv(1024)
print(f"Encrypted response: {encrypted_response}")
decrypted_response = cipher_suite.decrypt(encrypted_response)
print(f"Decrypted response: {decrypted_response.decode()}")

client_socket.close()



