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
SERVER_DIR = os.path.join(BASE_DIR, "SERVER")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
SERVER_PRIVKEY = os.path.join(SERVER_DIR, "sc1_private_key.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "sc1_public_key.pem")
CONFIG_FILE = os.path.join(SHARED_FOLDER, "server_config.txt")

active_clients = {}
client_lock = threading.Lock()
server_running = True  

def setup_directories():
    os.makedirs(SHARED_FOLDER, exist_ok=True)
    os.makedirs(SERVER_DIR, exist_ok=True)

def generate_server_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(SERVER_PRIVKEY, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    
    with open(SERVER_PUBKEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    
    print("Server keys generated")
    return private_key, public_key

def load_or_generate_keys():
    if os.path.exists(SERVER_PRIVKEY) and os.path.exists(SERVER_PUBKEY):
        try:
            with open(SERVER_PRIVKEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None)
            with open(SERVER_PUBKEY, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read()
                )
            return private_key, public_key
        except Exception:
            print("Generating new keys")
    
    return generate_server_keys()

def write_server_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    
    with open(CONFIG_FILE, "w") as f:
        f.write(local_ip)
    print(f"Server IP ({local_ip}) written to {CONFIG_FILE}")

def encrypt_large_data(data, client_public_key):
    max_chunk_size = 190 
    chunks = []
    data_bytes = data.encode()
    
    for i in range(0, len(data_bytes), max_chunk_size):
        chunk = data_bytes[i:i + max_chunk_size]
        encrypted_chunk = client_public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
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
                label=None))
        decrypted_data += decrypted_chunk
    
    return decrypted_data.decode()

def handle_client(client_socket, client_addr, private_key):
    global server_running
    client_id = f"{client_addr[0]}:{client_addr[1]}"
    
    try:
        client_public_key_data = client_socket.recv(2048)
        if not client_public_key_data:
            print(f"Client {client_id} disconnected")
            return
        
        try:
            client_public_key = serialization.load_pem_public_key(client_public_key_data)
            print(f"Client {client_id}'s public key loaded")
            
            with client_lock:
                active_clients[client_id] = {
                    "socket": client_socket,
                    "public_key": client_public_key
                }
            
            ##need to send - refer to dig
            ack_message = "CONNECTION_ESTABLISHED"
            encrypted_ack = client_public_key.encrypt(
                ack_message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_ack)
            
            while server_running:
                try:
                    encrypted_data = client_socket.recv(4096)
                    if not encrypted_data:
                        print(f"Client {client_id} disconnected")
                        break
                    
                    try:
                        decrypted_command = decrypt_large_data(encrypted_data, private_key)
                        print(f"Command from {client_id}: {decrypted_command}")
                        
                        if decrypted_command.lower() == "client-end":
                            encrypted_response = encrypt_large_data(
                                "Connection terminated", 
                                client_public_key
                            )
                            client_socket.send(encrypted_response)
                            break
                        elif decrypted_command.lower() == "server-end":
                            encrypted_response = encrypt_large_data(
                                "Server shutting down", 
                                client_public_key
                            )
                            client_socket.send(encrypted_response)
                            server_running = False
                            os.kill(os.getpid(), signal.SIGINT)
                            break
                        
                        try:
                            result = os.popen(decrypted_command).read()
                            if not result:
                                result = f"Error ; Command {decrypted_command} executed with no output"
                        except Exception as e:
                            result = f"Error executing command: {str(e)}"
                        
                        # Encrypt and send result
                        encrypted_result = encrypt_large_data(result, client_public_key)
                        client_socket.send(encrypted_result)
                        
                    except Exception as e:
                        print(f"Error with command from {client_id}: {str(e)}")
                        encrypted_error = encrypt_large_data(
                            f"Server error: {str(e)}", 
                            client_public_key
                        )
                        client_socket.send(encrypted_error)
                
                except ConnectionError:
                    print(f"Connection with {client_id} lost")
                    break
                except Exception as e:
                    print(f"Unexpected error with {client_id}: {str(e)}")
                    break
        
        except Exception as e:
            print(f"Error loading client's public key: {str(e)}")
    
    finally:
        with client_lock:
            if client_id in active_clients:
                del active_clients[client_id]
        
        try:
            client_socket.close()
            print(f"Connection with {client_id} closed")
        except:
            pass


def start_server():
    global server_running ###didint work before, make it global
    setup_directories()
    private_key, public_key = load_or_generate_keys()
    write_server_ip()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', 9222)) 
        server_socket.listen(5)
        print("Waiting for connections")
        
        while server_running:
            try:
                server_socket.settimeout(1.0)
                try:
                    client_socket, client_addr = server_socket.accept()
                    print(f"Connected with {client_addr[0]}:{client_addr[1]}")
                    
                    client_thread = threading.Thread(
                        target=handle_client, 
                        args=(client_socket, client_addr, private_key)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error connecting: {str(e)}")
                if not server_running:
                    break
                time.sleep(1)  
        
    except Exception as e:
        print(f"Server error: {str(e)}")
    
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

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    start_server()