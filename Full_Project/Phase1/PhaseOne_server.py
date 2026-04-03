import threading
import socket
import os

host = socket.gethostbyname(socket.gethostname()) 
port = 9222

with open("server_config.txt", "w") as config_file:
    config_file.write(host)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen()

clients = []

def execute_command(command):
    result = os.popen(command).read()  
    return result

def handle_client(client_socket, nickname):
    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8')
            if command.lower() == "client-end":
                client_socket.send("Connection closed by client.".encode('utf-8'))
                break
            if command:
                print(f"Received command from {nickname}: {command}")
                output = execute_command(command)
                client_socket.send(output.encode('utf-8'))
        except Exception as e:
            print(f"Error: {e}")
            clients.remove(client_socket)
            client_socket.close()
            break

def broadcast(msg, sender_socket):
    for client in clients:
        if client != sender_socket:
            client.send(msg.encode('utf-8'))

def receive_connections():
    while True:
        client_socket, address = server.accept()
        nickname = client_socket.recv(1024).decode('utf-8')
        print(f"Connected with {str(address)} ({nickname})")
        clients.append(client_socket)
        broadcast(f'{nickname} joined the server.', client_socket)

        thread = threading.Thread(target=handle_client, args=(client_socket, nickname))
        thread.start()

print(f"Server listening on {host}:{port}...")
receive_connections()
