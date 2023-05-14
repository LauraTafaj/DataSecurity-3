# server_gui.py
import base64
import socket
import threading
from tkinter import *
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def run_server():
    global server_socket

    while True:
        client_socket, addr = server_socket.accept()
        log(f"Klienti i lidhur: {addr}")

        # Prano mesazhin e kriptuar dhe dekriptoje
        encrypted_message = client_socket.recv(1024)
        log(f"Mesazhi i kriptuar: {encrypted_message}")
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        log(f"Mesazhi i dekriptuar: {decrypted_message.decode()}")

        # Dërgo mesazhin e përgjigjes të kriptuar
        response = "Mesazhi u pranua."
        encrypted_response = cipher_suite.encrypt(response.encode())
        log(f"Mesazhi i kriptuar i përgjigjes: {encrypted_response}")
        client_socket.send(encrypted_response)

        client_socket.close()

def log(message):
    messages_listbox.insert(END, message)

# Lexo certifikatën dhe çelësin privat
with open('C:\\ssl\\server.crt', "rb") as cert_file:
    cert = x509.load_pem_x509_certificate(cert_file.read())
with open('C:\\ssl\\server.key', "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Krijo një çelës Fernet duke përdorur çelësin publik të certifikatës
key = cert.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)

# Use HKDF to derive a 32-byte key from the public key
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=None,
)

derived_key = hkdf.derive(key)
cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))

# Krijo socket-in e serverit
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12565))
server_socket.listen(1)

# Krijo GUI-në e serverit
root = Tk()
root.title("Serveri")

messages_listbox = Listbox(root, width=100, height=20)
messages_listbox.pack()

threading.Thread(target=run_server, daemon=True).start()

# Shto mesazhin "Serveri është gati për të pritur klientë..." në GUI
log("Serveri është gati për të pritur klientë...")

root.mainloop()
