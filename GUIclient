# client_gui.py
import base64
import socket
from tkinter import *
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def send_message():
    global client_socket

   
    message = message_entry.get()
    encrypted_message = cipher_suite.encrypt(message.encode())
    log(f"Encrypted message: {encrypted_message}")
    client_socket.send(encrypted_message)

   
    encrypted_response = client_socket.recv(1024)
    log(f"Encrypted response: {encrypted_response}")
    decrypted_response = cipher_suite.decrypt(encrypted_response)
    log(f"Decrypted response: {decrypted_response.decode()}")

def log(message):
    messages_listbox.insert(END, message)


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
client_socket.connect(('localhost', 12565))


root = Tk()
root.title("Klienti")

messages_listbox = Listbox(root, width=100, height=20)
messages_listbox.pack()

message_entry = Entry(root, width=50)
message_entry.pack()

send_button = Button(root, text="Dërgo mesazhin", command=send_message)
send_button.pack()

root.mainloop()

client_socket.close()
