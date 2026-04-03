
import socket
import os
import time
import json
import threading
import signal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.getcwd()
CLIENT_DIR = os.path.join(BASE_DIR, "CLIENT")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
CLIENT_PRIVKEY = os.path.join(CLIENT_DIR, "sc2_private_key.pem")
CLIENT_PUBKEY = os.path.join(SHARED_FOLDER, "sc2_public_key.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "sc1_public_key.pem")
CONFIG_FILE = os.path.join(SHARED_FOLDER, "server_config.txt")

client_running = True ##initialise

def setup_directories():
    os.makedirs(SHARED_FOLDER, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)

def generate_client_keys():
    """Generate and save client's RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(CLIENT_PRIVKEY, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CLIENT_PUBKEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def load_or_generate_keys():
    if os.path.exists(CLIENT_PRIVKEY) and os.path.exists(CLIENT_PUBKEY):
        try:
            with open(CLIENT_PRIVKEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            with open(CLIENT_PUBKEY, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read()
                )
            print("Client keys loaded")
            return private_key, public_key
        except:
            print("Error loading keys - generating new ones")
    
    return generate_client_keys()

def wait_for_server_key(max_attempts=30, delay=2):
    for attempt in range(max_attempts):
        if os.path.exists(SERVER_PUBKEY):
            try:
                with open(SERVER_PUBKEY, "rb") as f:
                    server_public_key = serialization.load_pem_public_key(f.read())
                print("Server's public key loaded")
                return server_public_key
            except:
                print("Waiting for server public key")
                time.sleep(delay)
        else:
            print("Waiting for server to generate keys")
            time.sleep(delay)
    
    raise Exception("Timed out")

def read_server_ip(max_attempts=30, delay=2):
    for attempt in range(max_attempts):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    server_ip = f.read().strip()
                if server_ip:
                    print(f"Server IP found")
                    return server_ip
            except:
                pass
        
        if attempt < max_attempts - 1:
            print("Waiting for server config")
            time.sleep(delay)
    
    raise Exception("Timed out waiting server config")

def encrypt_large_data(data, server_public_key):
    max_chunk_size = 190
    chunks = []
    data_bytes = data.encode()
    
    for i in range(0, len(data_bytes), max_chunk_size):
        chunk = data_bytes[i:i + max_chunk_size]
        encrypted_chunk = server_public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        chunks.append(encrypted_chunk)
    
    metadata = len(chunks).to_bytes(4, byteorder='big')
    
    return metadata + b''.join(chunks)

def decrypt_large_data(encrypted_data, private_key):
    num_chunks = int.from_bytes(encrypted_data[:4], byteorder='big')
    encrypted_data = encrypted_data[4:]
    chunk_size = len(encrypted_data) // num_chunks
    
    decrypted_data = b''
    for i in range(num_chunks):
        chunk = encrypted_data[i * chunk_size:(i + 1) * chunk_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data += decrypted_chunk
    
    return decrypted_data.decode()

def connect_to_server(server_ip, port=9222, max_attempts=5, retry_delay=2):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    for attempt in range(max_attempts):
        try:
            client_socket.connect((server_ip, port))
            print(f"Connected to server {server_ip}:{port}")
            return client_socket
        except:
            if attempt < max_attempts - 1:
                print(f"Connection attempt {attempt+1} failed")
                time.sleep(retry_delay)
    
    raise Exception("Failed to connect to server")

def print_help():
    print("\n***HELP MESSAGE***")
    print("  Available commands: whoami, pwd, ip addr, ls, etc.")
    print("  End the client connection: client-end")
    print("  Shutdown the server: server-end")
    print("  Clear the screen: clear")

def main():
    global client_running
    
    try:
        setup_directories()
        private_key, public_key = load_or_generate_keys()
        
        try:
            server_ip = read_server_ip()
            server_public_key = wait_for_server_key()
        except Exception as e:
            print(f"Error: {e}")
            print("Make sure the server is running")
            return
        
        try:
            client_socket = connect_to_server(server_ip)
            client_socket.send(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            encrypted_ack = client_socket.recv(1024)
            decrypted_ack = private_key.decrypt(
                encrypted_ack,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            
            if decrypted_ack != "CONNECTION_ESTABLISHED":
                print(f"error in repsonse: {decrypted_ack}")
                client_socket.close()
                return
            
            print("Send a command to server, or type 'help' to show help message")
            
            while client_running:
                try:
                    command = input("\n> ")
                    
                    if not command.strip():
                        continue
                    
                    if command.lower() == "help":
                        print_help()
                        continue
                    elif command.lower() == "clear":
                        os.system('clear' if os.name == 'posix' else 'cls')
                        continue
                    
                    encrypted_command = encrypt_large_data(command, server_public_key)
                    client_socket.send(encrypted_command)
                    
                    if command.lower() in ["client-end", "server-end"]:
                        encrypted_response = client_socket.recv(4096)
                        if encrypted_response:
                            try:
                                response = decrypt_large_data(encrypted_response, private_key)
                                print(f"Server response: {response}")
                            except:
                                print("Error decrypting final response")
                        
                        if command.lower() == "client-end":
                            print("Connection terminated")
                            break
                        else: 
                            print("Server shutdown initiated")
                            break
                    
                    encrypted_response = client_socket.recv(4096)
                    if not encrypted_response:
                        print("Server closed connection")
                        break
                    
                    try:
                        response = decrypt_large_data(encrypted_response, private_key)
                        print(f"\nServer Response:\n{response}")
                    except:
                        print("Error server response")
                
                except KeyboardInterrupt:
                    print("\nUse 'client-end' to exit")
                    continue
                except Exception as e:
                    print(f"Command error: {e}")
                    break
            
        except Exception as e:
            print(f"error: {e}")
        
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    except Exception as e:
        print(f"error: {e}")
    
    print("Client terminated")

def signal_handler(sig, frame):
    global client_running
    client_running = False

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    main()