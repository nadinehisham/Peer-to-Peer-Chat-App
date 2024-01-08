import socket
import threading
import pymongo as py
import json
import bcrypt
import hashlib
from bson import json_util

rooms={}
connected_clients = []
client_lock = threading.Lock()
connected_clients_usernames = []

class Room:
    def __init__(self, room_name):
        self.room_id = room_name
        self.members = []

    def add_member(self, client_socket, username):
        self.members.append((client_socket, username))

    def remove_member(self, client_socket):
        self.members = [(s, u) for s, u in self.members if s != client_socket]

    def broadcast_message(self, message, sender_username):
        formatted_message = f"{sender_username}: {message}"
        for member_socket, _ in self.members:
            try:
                member_socket.send(formatted_message.encode('utf-8'))
            except:
                # Remove the client if there is an issue with sending the message
                self.remove_member(member_socket)

    def get_member_usernames(self):
        return [username for _, username in self.members]

def list_rooms():
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection2 = db["available_rooms"]
  
    online_rooms_cursor = users_collection2.find()
    

    online_room_list = []
    for user in online_rooms_cursor:
        online_room_list.append({"Room_name": user["Room_name"]})
        
    return online_room_list
    

def list_ips():
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection1 = db["online_list"]
  
    online_users_cursor = users_collection1.find()
    

    online_user_ips = []
    for user in online_users_cursor:
        online_user_ips.append({"client_ip": user["client_ip"],"client_port":user["client_port"]})

    return online_user_ips

def list_online_users():
    # Connect to MongoDB
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection1 = db["online_list"]
  
    online_users_cursor = users_collection1.find()
    

    online_user_list = []
    for user in online_users_cursor:
        online_user_list.append({"username": user["username"]})
        
    return online_user_list



def authenticate(username, password,client_ip,client_port):
    # Connect to MongoDB
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection = db["student"]
    
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # Check if the username exists in the database
    
    stored_user = users_collection.find_one({'username': username})
    

    if stored_user and hashed_password == stored_user['password']:
        users_collection2= db["online_list"]
        user_data = {"username": username,"client_ip":client_ip,"client_port":client_port}
        users_collection2.insert_one(user_data)
        # Verify the password
        # Password is correct, authentication successful 
        return True
    else:
        # User not found
        return False


def register_user(username, password,client_ip,client_port):
    # Connect to MongoDB
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection = db["student"]
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # Check if the username already exists
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        return False, "Username already exists"
 
    # If the username doesn't exist, insert the new user
    result = users_collection.insert_one({'username': username, 'password':hashed_password  })
    users_collection2= db["online_list"]
    user_data2 = {"username": username,"client_ip":client_ip,"client_port":client_port}
    users_collection2.insert_one(user_data2)

    if result.inserted_id:
        return True, str(result.inserted_id)
    else:
        return False, "Registration failed"

def handle_client(client_socket, username):
    

    with client_lock:
     connected_clients.append(client_socket)
     # Notify other clients about the new connection
     client_socket.send(f"{username} joined the connection!".encode('utf-8'))
     print(f"{username} joined the connection!")

    while True:
        # Receive and broadcast messages
        message = client_socket.recv(1024).decode('utf-8')
        if message==":list":
           online_users = list_online_users()
           online_users_json = json.dumps(online_users)
           client_socket.sendall(online_users_json.encode('utf-8'))
            
          
        elif message==":logout":
            client = py.MongoClient('mongodb://localhost:27017/')
            db = client["config"]
            users_collection = db["online_list"]
            users_collection.delete_one({"username": username})
            print(f"closed connection from {username}")
            break

        elif message==":search":
             client = py.MongoClient('mongodb://localhost:27017/')
             db = client["config"]
             users_collection = db["student"]
             username1=client_socket.recv(1024).decode('utf-8')

             existing_user = users_collection.find_one({"username": username1})

             if existing_user:
                 client_socket.send("user is found".encode('utf-8'))
             else:
                 client_socket.send("user is not found".encode('utf-8'))



        elif message==":search_user":
             client = py.MongoClient('mongodb://localhost:27017/')
             db = client["config"]
             users_collection = db["online_list"]
             username1=client_socket.recv(1024).decode('utf-8')

             existing_user = users_collection.find_one({"username": username1})
             
             if existing_user:
                 online_user = json.dumps(existing_user ,default=json_util.default)
                 client_socket.send(online_user.encode('utf-8'))
             else:
                 client_socket.send("user is not found".encode('utf-8'))         

        elif message.startswith("join room"):
            room_id = message.split()[2]
            
            join_room(client_socket, username, room_id)

        elif message.startswith(":leave"):
            leave_room(client_socket, username)

        elif message.startswith("create room"):
            room_name=client_socket.recv(1024).decode('utf-8')
            create_room(client_socket, room_name,username)
        elif message.startswith(":list rooms"):
            online_rooms = list_rooms()
            online_rooms_json = json.dumps( online_rooms)
            client_socket.sendall(online_rooms_json.encode('utf-8'))
        else:
            continue
        

        
 
    with client_lock:
      connected_clients.remove(client_socket)
     
      
    # Close the connection
    client_socket.close()
    
def join_room(client_socket, username, room_name):
   global rooms
   if room_name in rooms:
        room = rooms[room_name]
        room.add_member(client_socket, username)
        online_users_ips = list_ips()
        online_users_list_json = json.dumps(online_users_ips)
        client_socket.sendall(online_users_list_json.encode('utf-8'))

      #  room.broadcast_message( "joined the room.", username)
       # room_thread = threading.Thread(target=handle_room_messages, args=(room, username,client_socket))
        #room_thread.start()
            
          
   else:
        client_socket.send("Room not found.".encode('utf-8'))
    

def handle_room_messages(room, username,client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message == "leave":
                leave_room(client_socket, username)
                client_socket.send("leave".encode('utf-8'))
                break
            else:
                room.broadcast_message(message, username)
        except Exception as e:
            print(f"Error handling room messages: {e}")
            break    

def leave_room(client_socket, username):
   global rooms
   for room_name, room in rooms.items():
        for member_socket, member_username in room.members:
            if client_socket == member_socket:
                room.remove_member(client_socket)
                return

def create_room(client_socket, room_name,username):
    # Create a new room
    global rooms
    room = Room(room_name)  # Using the username as the room name
    rooms[room.room_id] = room
    room.add_member(client_socket, username)
    client = py.MongoClient('mongodb://localhost:27017/')
    db = client["config"]
    users_collection2 = db["available_rooms"]
    user_data = {"Room_name": room_name}
    users_collection2.insert_one(user_data)
    
  
    client_socket.send(f"Room created with ID: {room.room_id}".encode('utf-8'))
    online_users_ips = list_ips()
    online_users_list_json = json.dumps(online_users_ips)
    client_socket.sendall(online_users_list_json.encode('utf-8'))
    #room_thread = threading.Thread(target=handle_room_messages, args=(room, username,client_socket))
    #room_thread.start()
     
def handle_room_messages(room, username,client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message == "leave":
                leave_room(client_socket, username)
                client_socket.send("leave".encode('utf-8'))
                break
            else:
                room.broadcast_message(message, username)
        except Exception as e:
            print(f"Error handling room messages: {e}")
            break          
def broadcast(message):
    # Send a message to all connected clients
    for client in connected_clients:
        try:
            client.send(message.encode('utf-8'))
        except:
            # Remove the client if there is an issue with sending the message
            connected_clients.remove(client)
        

def main():
    # Setup the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    
    print("Server listening on port 12345...")
    
    while True:
        # Accept a connection
        client_socket, addr = server_socket.accept()
        client_ip = addr[0]
        client_port = addr[1]
        print(f"Accepted connection from {client_ip}: {client_port}")
        
        choice= client_socket.recv(1024).decode('utf-8')
        
        if choice==":login":
            username = client_socket.recv(1024).decode('utf-8')
            password = client_socket.recv(1024).decode('utf-8')
            # Perform authentication
            if authenticate(username, password,client_ip,client_port):
              client_socket.send("Authentication successful".encode('utf-8'))
              # Create a new thread to handle the client
              client_thread = threading.Thread(target=(handle_client), args=(client_socket, username))
              client_thread.start()
              
            else:
              client_socket.send("Authentication failed".encode('utf-8'))
              client_socket.close()
            
        elif choice==":signup":
            new_username = client_socket.recv(1024).decode('utf-8')
            new_password = client_socket.recv(1024).decode('utf-8')
            

            registered, user_id = register_user(new_username, new_password,client_ip,client_port)
            if registered:
                client_socket.send("user is register successfully".encode('utf-8'))
                client_thread = threading.Thread(target=(handle_client), args=(client_socket,new_username))
                client_thread.start()
            else:
                client_socket.send(user_id.encode('utf-8'))
                client_socket.close()    
            
    
        
        

if __name__ == "__main__":
    main()