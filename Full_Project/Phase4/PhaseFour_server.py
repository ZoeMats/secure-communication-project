import socket
import os
import time
import json
import threading
import signal
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import datetime
import warnings


warnings.filterwarnings("ignore")

BASE_DIR = os.getcwd()
SERVER_DIR = os.path.join(BASE_DIR, "SERVER")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
SERVER_PRIVKEY = os.path.join(SERVER_DIR, "sc1_private_key.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "sc1_public_key.pem")
SERVER_CERT = os.path.join(SHARED_FOLDER, "sc1_certificate.pem")
CONFIG_FILE = os.path.join(SHARED_FOLDER, "server_config.txt")
active_clients = {}
client_lock = threading.Lock()
server_running = True 

def setup_directories():
    os.makedirs(SHARED_FOLDER, exist_ok=True)
    os.makedirs(SERVER_DIR, exist_ok=True)

def generate_server_keys_and_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(SERVER_PRIVKEY, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(SERVER_PUBKEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Entreprise"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"sc1.local"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    with open(SERVER_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return private_key, public_key, cert

def load_or_generate_keys_and_certificate():
    if os.path.exists(SERVER_PRIVKEY) and os.path.exists(SERVER_PUBKEY) and os.path.exists(SERVER_CERT):
        try:
            with open(SERVER_PRIVKEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            with open(SERVER_PUBKEY, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read()
                )
            with open(SERVER_CERT, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            now = datetime.datetime.now(datetime.UTC)
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return generate_server_keys_and_certificate()
                
            return private_key, public_key, cert
        except Exception as e:
            print("Generating new keys and certificate")
    return generate_server_keys_and_certificate()

def write_server_ip(server_ip):
    with open(CONFIG_FILE, "w") as f:
        f.write(server_ip)
    print(f"Server IP ({server_ip}) written to {CONFIG_FILE}")

def create_digital_signature(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())
    return signature

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256())
        return True
    except Exception:
        return False

def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def aes_encrypt(data, key, iv):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padded_data = data + bytes([padding_length] * padding_length)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def handle_client(client_socket, client_addr, private_key, server_cert):
    global server_running  
    client_id = f"{client_addr[0]}:{client_addr[1]}"

    try:
        cert_data = server_cert.public_bytes(serialization.Encoding.PEM)
        cert_length = len(cert_data).to_bytes(4, byteorder='big')
        client_socket.sendall(cert_length + cert_data)
        cert_length_data = client_socket.recv(4)
        if not cert_length_data:
            print(f"Client {client_id} disconnected")
            return
            
        cert_length = int.from_bytes(cert_length_data, byteorder='big')
        client_cert_data = client_socket.recv(cert_length)
        
        try:
            client_cert = x509.load_pem_x509_certificate(client_cert_data)
            client_public_key = client_cert.public_key()
            print(f"Client {client_id}'s certificate loaded and public key extracted")
            length_data = client_socket.recv(4)
            if not length_data:
                print(f"Client {client_id} disconnected")
                return
                
            package_length = int.from_bytes(length_data, byteorder='big')
            encrypted_package = client_socket.recv(package_length)
            sig_length_data = client_socket.recv(4)
            if not sig_length_data:
                print(f"Client {client_id} disconnected")
                return
                
            sig_length = int.from_bytes(sig_length_data, byteorder='big')
            signature = client_socket.recv(sig_length)
            if not verify_signature(encrypted_package, signature, client_public_key):
                print(f"Signature verification failed for client {client_id}")
                client_socket.close()
                return
                
            print(f"Signature from client {client_id} verified")

            try:
                key_package = private_key.decrypt(
                    encrypted_package,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))
            
                aes_key = key_package[:32]
                aes_iv = key_package[32:48]
            
                with client_lock:
                    active_clients[client_id] = {
                        "socket": client_socket,
                        "public_key": client_public_key,
                        "certificate": client_cert,
                        "aes_key": aes_key,
                        "aes_iv": aes_iv
                    }

            except Exception:
                return

        except Exception:
            return

        try:
            ack_message = "connection is established"
            encrypted_ack = aes_encrypt(ack_message.encode(), aes_key, aes_iv)
            signature = create_digital_signature(encrypted_ack, private_key)
            message_length = len(encrypted_ack).to_bytes(4, byteorder='big')
            client_socket.sendall(message_length + encrypted_ack)
            sig_length = len(signature).to_bytes(4, byteorder='big')
            client_socket.sendall(sig_length + signature)
            
        except Exception:
            print(f"Error")
                
        while server_running:
            try:
                length_data = client_socket.recv(4)
                if not length_data or len(length_data) < 4:
                    print(f"Client {client_id} disconnected")
                    break
            
                message_length = int.from_bytes(length_data, byteorder='big')
                encrypted_data = client_socket.recv(message_length)
                if not encrypted_data or len(encrypted_data) < message_length:
                    print(f"Client {client_id} disconnected")
                    break
                    
                sig_length_data = client_socket.recv(4)
                if not sig_length_data or len(sig_length_data) < 4:
                    print(f"Client {client_id} disconnected")
                    break
                    
                sig_length = int.from_bytes(sig_length_data, byteorder='big')
                signature = client_socket.recv(sig_length)
                
                if not verify_signature(encrypted_data, signature, client_public_key):
                    print(f"Command signature verification failed for client {client_id}")
                    response = "ERROR: Command signature verification failed"
                    encrypted_response = aes_encrypt(response.encode(), aes_key, aes_iv)
                    signature = create_digital_signature(encrypted_response, private_key)
                    message_length = len(encrypted_response).to_bytes(4, byteorder='big')
                    client_socket.sendall(message_length + encrypted_response)
                    sig_length = len(signature).to_bytes(4, byteorder='big')
                    client_socket.sendall(sig_length + signature)
                    continue
            
                decrypted_command_bytes = aes_decrypt(encrypted_data, aes_key, aes_iv)
                decrypted_command = decrypted_command_bytes.decode()
                print(f"Command from {client_id}: {decrypted_command}")

                if decrypted_command.lower() == "client-end":
                    response = "Connection terminated"
                    encrypted_response = aes_encrypt(response.encode(), aes_key, aes_iv)
                    signature = create_digital_signature(encrypted_response, private_key)
                    message_length = len(encrypted_response).to_bytes(4, byteorder='big')
                    client_socket.sendall(message_length + encrypted_response)
                    sig_length = len(signature).to_bytes(4, byteorder='big')
                    client_socket.sendall(sig_length + signature)
                    break
                elif decrypted_command.lower() == "server-end":
                    response = "Server shutting down"
                    encrypted_response = aes_encrypt(response.encode(), aes_key, aes_iv)
                    signature = create_digital_signature(encrypted_response, private_key)
                    
                    message_length = len(encrypted_response).to_bytes(4, byteorder='big')
                    client_socket.sendall(message_length + encrypted_response)
                    sig_length = len(signature).to_bytes(4, byteorder='big')
                    client_socket.sendall(sig_length + signature)
                    server_running = False
                    os.kill(os.getpid(), signal.SIGINT)
                    break
            
                try:
                    result = os.popen(decrypted_command).read()
                    if not result:
                        result = f"Command '{decrypted_command}' executed with no output"
                except Exception:
                    result = f"Error executing command"
            
                encrypted_result = aes_encrypt(result.encode(), aes_key, aes_iv)
                signature = create_digital_signature(encrypted_result, private_key)
                message_length = len(encrypted_result).to_bytes(4, byteorder='big')
                client_socket.sendall(message_length + encrypted_result)
                sig_length = len(signature).to_bytes(4, byteorder='big')
                client_socket.sendall(sig_length + signature)
            
            except ConnectionError:
                break
            except Exception:
                break

    finally:
        with client_lock:
            if client_id in active_clients:
                del active_clients[client_id]

        try:
            client_socket.close()
            print(f"Connection with {client_id} closed")
        except:
            pass


def start_server(server_ip):
    global server_running 
    setup_directories()
    private_key, public_key, server_cert = load_or_generate_keys_and_certificate()
    write_server_ip(server_ip)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', 9222))  
        server_socket.listen(5)
        
        while server_running:
            try:
                server_socket.settimeout(1.0)
                try:
                    client_socket, client_addr = server_socket.accept()
                    print(f"Connected with {client_addr[0]}:{client_addr[1]}")
                    
                    client_thread = threading.Thread(
                        target=handle_client, 
                        args=(client_socket, client_addr, private_key, server_cert)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                    
            except KeyboardInterrupt:
                break
            except Exception:
                if not server_running:
                    break
                time.sleep(1)  
        
    except Exception:
        print(f"Server error")
    
    finally:
        print("\nShutting down server")
        
        with client_lock:
            for client_id, client_data in active_clients.items():
                try:
                    client_data["socket"].close()
                    print(f"Closed connection with {client_id}")
                except:
                    pass
            active_clients.clear()
        
        try:
            server_socket.close()
        except:
            pass

def signal_handler(sig, frame):
    global server_running
    server_running = False

def show_ip_address_help():
    print("\nERROR: Missing IP address parameter")
    print("\nPlease provide your server's IP address as a parameter.")
    print("\nTo find your IP address, you can use the command:")
    print("    hostname -I (first address)")
    print("\nThen run the server with:")
    print("    python3 <script_name> <ip_address>")
    print("\nExample:")
    print("    python3 server.py 192.168.1.100")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        show_ip_address_help()
        sys.exit(1)
        
    server_ip = sys.argv[1]
    print(f"Server listening on IP {server_ip}.......")
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    start_server(server_ip)