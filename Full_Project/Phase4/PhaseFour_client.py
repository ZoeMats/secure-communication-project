import socket
import os
import time
import json
import threading
import signal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import secrets
import datetime
import warnings


warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
CLIENT_DIR = os.path.join(BASE_DIR, "CLIENT")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
CLIENT_PRIVKEY = os.path.join(CLIENT_DIR, "sc2_private_key.pem")
CLIENT_PUBKEY = os.path.join(SHARED_FOLDER, "sc2_public_key.pem")
CLIENT_CERT = os.path.join(SHARED_FOLDER, "sc2_certificate.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "sc1_public_key.pem")
SERVER_CERT = os.path.join(SHARED_FOLDER, "sc1_certificate.pem")
CONFIG_FILE = os.path.join(SHARED_FOLDER, "server_config.txt")
client_running = True
client_socket = None

def signal_handler(sig, frame):
    print("Terminating client...")
    if client_socket:
        client_socket.close()
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def setup_directories():
    os.makedirs(SHARED_FOLDER, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)

def generate_client_keys_and_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    public_key = private_key.public_key()

    with open(CLIENT_PRIVKEY, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))

    with open(CLIENT_PUBKEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Entreprise"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"sc2.local")])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    with open(CLIENT_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("Client keys and certificate generated and saved")
    return private_key, public_key, cert

def load_or_generate_keys_and_certificate():
    if os.path.exists(CLIENT_PRIVKEY) and os.path.exists(CLIENT_PUBKEY) and os.path.exists(CLIENT_CERT):
        try:
            with open(CLIENT_PRIVKEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None)
            with open(CLIENT_PUBKEY, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read())
            with open(CLIENT_CERT, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                print("Certificate expired or not yet valid, generating new ones")
                return generate_client_keys_and_certificate()
                
            print("Client keys and certificate loaded")
            return private_key, public_key, cert
        except Exception:
            print("Generating new keys and certificate")
    
    return generate_client_keys_and_certificate()

def wait_for_server_config(max_attempts=30, delay=2):
    for attempt in range(max_attempts):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    server_ip = f.read().strip()
                if server_ip:
                    print(f"Server IP found: {server_ip}")
                    return server_ip
            except:
                pass
        
        print(f"Waiting for server")
        time.sleep(delay)

def create_digital_signature(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        print(f"Signature verification failed")
        return False

def generate_aes_key_and_iv():
    key = secrets.token_bytes(32) 
    iv = secrets.token_bytes(16)
    return key, iv

def aes_encrypt(data, key, iv):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padded_data = data + bytes([padding_length] * padding_length)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def connect_to_server(server_ip, port=9222, max_attempts=5, retry_delay=2):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    for attempt in range(max_attempts):
        try:
            client_socket.connect((server_ip, port))
            print(f"Connected to server at {server_ip}:{port}")
            return client_socket
        except Exception:
            if attempt < max_attempts - 1:
                time.sleep(retry_delay)
            else:
                raise Exception(f"Failed to connect to server")
    
    raise Exception("Failed to connect to server after multiple attempts")

def print_help():
    print("\n***HELP MESSAGE***")
    print("  Available commands: whoami, pwd, ip addr, ls, etc.")
    print("  End the client connection: client-end")
    print("  Shutdown the server: server-end")
    print("  Show certificate information: show-cert")

def show_certificate_info(cert):
    print("\n***CERTIFICATE INFORMATION***")
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Signature Algorithm: {cert.signature_hash_algorithm.name}")
    
    for ext in cert.extensions:
        print(f"Extension: {ext.oid._name}")
        if ext.oid._name == 'subjectAltName':
            print(f"  {ext.value}")

def main():
    global client_running

    try:
        setup_directories()
        private_key, public_key, client_cert = load_or_generate_keys_and_certificate()
        
        try:
            server_ip = wait_for_server_config()
        except Exception:
            print(f"Error")
            return
        
        try:
            client_socket = connect_to_server(server_ip)
            cert_length_data = client_socket.recv(4)
            if not cert_length_data or len(cert_length_data) < 4:
                return
            
            cert_length = int.from_bytes(cert_length_data, byteorder='big')
            server_cert_data = client_socket.recv(cert_length)
            
            try:
                server_cert = x509.load_pem_x509_certificate(server_cert_data)
                server_public_key = server_cert.public_key()
                print("Server certificate received and public key extracted")
            except Exception:
                print(f"Error loading server certificate")
                return
            
            client_cert_data = client_cert.public_bytes(serialization.Encoding.PEM)
            cert_length = len(client_cert_data).to_bytes(4, byteorder='big')
            client_socket.sendall(cert_length + client_cert_data)
            aes_key, aes_iv = generate_aes_key_and_iv()
            print("Generated AES encryption keys")
            key_package = aes_key + aes_iv 
            encrypted_package = server_public_key.encrypt(
                key_package,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            
            signature = create_digital_signature(encrypted_package, private_key)
            package_length = len(encrypted_package).to_bytes(4, byteorder='big')
            client_socket.sendall(package_length + encrypted_package)
            sig_length = len(signature).to_bytes(4, byteorder='big')
            client_socket.sendall(sig_length + signature)
            ack_length_data = client_socket.recv(4)
            if not ack_length_data or len(ack_length_data) < 4:
                print("Failed to receive acknowledgment length")
                return
            
            ack_length = int.from_bytes(ack_length_data, byteorder='big')
            encrypted_ack = client_socket.recv(ack_length)
            sig_length_data = client_socket.recv(4)
            if not sig_length_data or len(sig_length_data) < 4:
                print("Failed to receive acknowledgment signature length")
                return
            
            sig_length = int.from_bytes(sig_length_data, byteorder='big')
            signature = client_socket.recv(sig_length)
            if not verify_signature(encrypted_ack, signature, server_public_key):
                print("Acknowledgment signature verification failed")
                return
            
            decrypted_ack = aes_decrypt(encrypted_ack, aes_key, aes_iv).decode()
            print(f"Server response: {decrypted_ack}")
            print("\nSecure connection established. Type commands or 'help' for assistance.")
            
            while client_running:
                try:
                    command = input("$ ")
                    if command.lower() == "help":
                        print_help()
                        continue
                    elif command.lower() == "clear":
                        os.system('clear')
                        continue
                    elif command.lower() == "show-cert":
                        show_certificate_info(server_cert)
                        continue
                    elif not command:
                        continue
                    
                    encrypted_command = aes_encrypt(command.encode(), aes_key, aes_iv)
                    signature = create_digital_signature(encrypted_command, private_key)
                    command_length = len(encrypted_command).to_bytes(4, byteorder='big')
                    client_socket.sendall(command_length + encrypted_command)
                    sig_length = len(signature).to_bytes(4, byteorder='big')
                    client_socket.sendall(sig_length + signature)
                    if command.lower() == "client-end" or command.lower() == "server-end":
                        resp_length_data = client_socket.recv(4)
                        if resp_length_data:
                            resp_length = int.from_bytes(resp_length_data, byteorder='big')
                            encrypted_resp = client_socket.recv(resp_length)
                            sig_length_data = client_socket.recv(4)
                            sig_length = int.from_bytes(sig_length_data, byteorder='big')
                            signature = client_socket.recv(sig_length)
                            if verify_signature(encrypted_resp, signature, server_public_key):
                                response = aes_decrypt(encrypted_resp, aes_key, aes_iv).decode()
                                print(f"Server response: {response}")
                        client_running = False
                        break

                    resp_length_data = client_socket.recv(4)
                    if not resp_length_data or len(resp_length_data) < 4:
                        print("problem with response length")
                        break
                    
                    resp_length = int.from_bytes(resp_length_data, byteorder='big')
                    encrypted_resp = client_socket.recv(resp_length)
                    sig_length_data = client_socket.recv(4)
                    if not sig_length_data or len(sig_length_data) < 4:
                        break
                    
                    sig_length = int.from_bytes(sig_length_data, byteorder='big')
                    signature = client_socket.recv(sig_length)
                    if not verify_signature(encrypted_resp, signature, server_public_key):
                        print("Response signature verification failed")
                        continue
                    response = aes_decrypt(encrypted_resp, aes_key, aes_iv).decode()
                    print(response)
                
                except ConnectionError:
                    print("Connection lost")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    if not client_running:
                        break
                    
        except Exception:
            print(f"error")
    
    except Exception:
        print(f"error")
    
    finally:
        print("Closing client connection")
        try:
            client_socket.close()
        except:
            pass

if __name__ == "__main__":
    main()