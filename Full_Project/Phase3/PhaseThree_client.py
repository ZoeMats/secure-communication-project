import socket
import os
import time
import signal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import warnings

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
CLIENT_DIR = os.path.join(BASE_DIR, "CLIENT")
SHARED_FOLDER = os.path.join(BASE_DIR, "SHARED")
CLIENT_PRIVKEY = os.path.join(CLIENT_DIR, "client_private_key.pem")
CLIENT_PUBKEY = os.path.join(SHARED_FOLDER, "client_public_key.pem")
SERVER_PUBKEY = os.path.join(SHARED_FOLDER, "server_public_key.pem")
CONFIG_FILE = os.path.join(SHARED_FOLDER, "server_config.txt")
client_running = True
client_socket = None

def signal_handler(sig, frame):
    print("Stopping client terminal")
    if client_socket:
        client_socket.close()
    os._exit(0) 

signal.signal(signal.SIGINT, signal_handler)

def setup_directories():
    os.makedirs(SHARED_FOLDER, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)

def generate_client_keys():
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
    
    print("Client keys generated and saved")
    return private_key, public_key

def load_or_generate_keys():
    if os.path.exists(CLIENT_PRIVKEY) and os.path.exists(CLIENT_PUBKEY):
        try:
            with open(CLIENT_PRIVKEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None)
            with open(CLIENT_PUBKEY, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read())
            return private_key, public_key
        except Exception as e:
            print(f"Error loading keys: {e}, generating new ones")
    
    return generate_client_keys()

def wait_for_server_config(max_attempts=30, delay=2):
    for attempt in range(max_attempts):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    server_ip = f.read().strip()
                if server_ip:
                    return server_ip
            except:
                pass
        ###if lcient connects before server, print waiting message for 30 secs
        print(f"Waiting for server configuration. (attempt {attempt+1}/{max_attempts})")
        time.sleep(delay)
    
    raise Exception("Failed to get server config")

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
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    for attempt in range(max_attempts):
        try:
            client_socket.connect((server_ip, port))
            print(f"Connected to server at {server_ip}:{port}")
            return client_socket
        except Exception as e:
            if attempt < max_attempts - 1:
                print(f"Connection attempt {attempt+1} failed: {e}. Retrying")
                time.sleep(retry_delay)
            else:
                raise Exception(f"Failed to connect to server: {e}")
    
    raise Exception("Failed to connect to server")

def print_help():
    print("\n***HELP MESSAGE***")
    print("  Available commands: whoami, pwd, ip addr, ls, etc.")
    print("  End the client connection: client-end")
    print("  Shutdown the server: server-end")
    print("  Clear the screen: clear")

def main():
    global client_running, client_socket

    try:
        setup_directories()
        private_key, public_key = load_or_generate_keys()
        
        try:
            server_ip = wait_for_server_config()
            print(f"Found server IP: {server_ip}")
        except Exception as e:
            print(f"Error finding server: {e}")
            return
        
        try:
            client_socket = connect_to_server(server_ip)
            
            # Receive server public key
            key_length_data = client_socket.recv(4)
            if not key_length_data or len(key_length_data) < 4:
                print("error server public key length")
                return
            
            key_length = int.from_bytes(key_length_data, byteorder='big')
            server_pubkey_data = client_socket.recv(key_length)
            
            try:
                server_public_key = serialization.load_pem_public_key(server_pubkey_data)
                print("Server public key received")
            except Exception as e:
                print(f"Error server public key: {e}")
                return
            
            # Generate and send AES key/IV
            aes_key, aes_iv = generate_aes_key_and_iv()
            key_package = aes_key + aes_iv  # Concatenate key and IV
            
            encrypted_package = server_public_key.encrypt(
                key_package,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            
            package_length = len(encrypted_package).to_bytes(4, byteorder='big')
            client_socket.sendall(package_length + encrypted_package)
            
            ack_length_data = client_socket.recv(4)
            if not ack_length_data or len(ack_length_data) < 4:
                print("Failed acknowledgment length")
                return
            
            ack_length = int.from_bytes(ack_length_data, byteorder='big')
            encrypted_ack = client_socket.recv(ack_length)
            
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
                        os.system('clear' if os.name != 'nt' else 'cls')
                        continue
                    elif not command:
                        continue
                    
                    encrypted_command = aes_encrypt(command.encode(), aes_key, aes_iv)
                    command_length = len(encrypted_command).to_bytes(4, byteorder='big')
                    client_socket.sendall(command_length + encrypted_command)
                    
                    if command.lower() == "client-end" or command.lower() == "server-end":
                        resp_length_data = client_socket.recv(4)
                        if resp_length_data:
                            resp_length = int.from_bytes(resp_length_data, byteorder='big')
                            encrypted_resp = client_socket.recv(resp_length)
                            response = aes_decrypt(encrypted_resp, aes_key, aes_iv).decode()
                            print(f"Server response: {response}")
                        client_running = False
                        break

                    resp_length_data = client_socket.recv(4)
                    if not resp_length_data or len(resp_length_data) < 4:
                        print("Problem with response length")
                        break
                    
                    resp_length = int.from_bytes(resp_length_data, byteorder='big')
                    encrypted_resp = client_socket.recv(resp_length)
                    
                    response = aes_decrypt(encrypted_resp, aes_key, aes_iv).decode()
                    print(response)
                
                except ConnectionError as e:
                    print(f"Connection lost: {e}")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    if not client_running:
                        break
                    
        except Exception as e:
            print(f"Error in client operation: {e}")
    
    except Exception as e:
        print(f"Client initialisation error: {e}")
    
    finally:
        print("Closing client connection")
        try:
            if client_socket:
                client_socket.close()
        except:
            pass

if __name__ == "__main__":
    main()