import socket
import os
import time
import threading
import signal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import warnings

warnings.filterwarnings("ignore")

BASE_DIR = os.getcwd()
SERVER_DIR = os.path.join(BASE_DIR, "SERVER")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
SERVER_PRIVKEY = os.path.join(SERVER_DIR, "server_private_key.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "server_public_key.pem")
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
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(SERVER_PUBKEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key, public_key

def load_or_generate_keys():
    if os.path.exists(SERVER_PRIVKEY) and os.path.exists(SERVER_PUBKEY):
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
            return private_key, public_key
        except Exception as e:
            print("Error loading keys, generating new ones")
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

def handle_client(client_socket, client_addr, private_key):
    global server_running
    client_id = f"{client_addr[0]}:{client_addr[1]}"

    try:
        with open(SERVER_PUBKEY, "rb") as f:
            pubkey_data = f.read()
        pubkey_length = len(pubkey_data).to_bytes(4, byteorder='big')
        client_socket.sendall(pubkey_length + pubkey_data)
        
        length_data = client_socket.recv(4)
        if not length_data:
            print(f"Client {client_id} disconnected")
            return
                
        package_length = int.from_bytes(length_data, byteorder='big')
        encrypted_package = client_socket.recv(package_length)
        
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
                    "aes_key": aes_key,
                    "aes_iv": aes_iv
                }
                
        except Exception as e:
            print(f"Failed to decrypt key package: {e}")
            return

        ack_message = "Connection established"
        encrypted_ack = aes_encrypt(ack_message.encode(), aes_key, aes_iv)
        message_length = len(encrypted_ack).to_bytes(4, byteorder='big')
        client_socket.sendall(message_length + encrypted_ack)
            
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
                    
                decrypted_command_bytes = aes_decrypt(encrypted_data, aes_key, aes_iv)
                decrypted_command = decrypted_command_bytes.decode()
                print(f"Command from {client_id}: {decrypted_command}")

                if decrypted_command.lower() == "client-end":
                    response = "Connection terminated"
                    encrypted_response = aes_encrypt(response.encode(), aes_key, aes_iv)
                    message_length = len(encrypted_response).to_bytes(4, byteorder='big')
                    client_socket.sendall(message_length + encrypted_response)
                    break
                elif decrypted_command.lower() == "server-end":
                    response = "Server shutting down"
                    encrypted_response = aes_encrypt(response.encode(), aes_key, aes_iv)
                    message_length = len(encrypted_response).to_bytes(4, byteorder='big')
                    client_socket.sendall(message_length + encrypted_response)
                    server_running = False
                    os.kill(os.getpid(), signal.SIGINT)
                    break
            
                try:
                    result = os.popen(decrypted_command).read()
                    if not result:
                        result = f"Command '{decrypted_command}' executed with no output"
                except Exception:
                    result = f"Error w command"
            
                encrypted_result = aes_encrypt(result.encode(), aes_key, aes_iv)
                message_length = len(encrypted_result).to_bytes(4, byteorder='big')
                client_socket.sendall(message_length + encrypted_result)
            
            except ConnectionError:
                break
            except Exception as e:
                print(f"Error processing command: {e}")
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

def start_server():
    global server_running
    setup_directories()
    private_key, public_key = load_or_generate_keys()
    write_server_ip()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', 9222))  # Listen on all IPs
        server_socket.listen(5)
        print("Server is listening for connections......")
        
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
                print(f"Error accepting connection: {e}")
                if not server_running:
                    break
                time.sleep(1)  # Avoid CPU spinning on repeated errors
        
    except Exception as e:
        print(f"Server error: {e}")
    
    finally:
        print("\nShutting down server")
        
        with client_lock:
            for client_id, client_data in active_clients.items():
                try:
                    client_data["socket"].close()
                    print(f"Closed connection  {client_id}")
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
    print("Server starting")
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    start_server()