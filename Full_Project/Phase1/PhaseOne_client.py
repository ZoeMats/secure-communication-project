import socket
import threading

def read_server_ip():
    try:
        with open("server_config.txt", "r") as config_file:
            server_ip = config_file.read().strip()
            return server_ip
    except FileNotFoundError:
        print("Config file not found")
        return None

def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(f"Server: {message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

server_ip = read_server_ip()
if server_ip is None:
    exit()

port = 9222
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, port))

nickname = input("Enter your nickname: ") #not really required, will drop in later phases
client_socket.send(nickname.encode('utf-8'))

print("Connected to server. Type commands below (use 'client-end' to end)") ##doesnt look nice, need to develop further and incorporate help 

thr = threading.Thread(target=receive_messages, daemon=True)
thr.start()

while True:
    command = input("You: ")
    if command.lower() == 'client-end':
        client_socket.send(command.encode('utf-8'))
        break
    client_socket.send(command.encode('utf-8'))

client_socket.close()
