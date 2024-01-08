from pickle import TRUE
from socket import *
import threading
import json
import bcrypt
import maskpass
import random

import select
from colorama import Fore, Style, init

init(autoreset=True) 


class PeerServer(threading.Thread):


    # Peer server initialization
    def __init__(self, username,peerServerip ,peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET,SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        self.peerServerip = peerServerip
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None

        
    

    # main method of the peer server thread
    def run(self):

        print("Peer server started...")    

        # gets the ip address of this peer
        # first checks to get it for windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macos devices
       
        # ip address of this peer
        #self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer
        self.tcpServerSocket.bind((self.peerServerip, self.peerServerPort))
        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline :
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is 
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:     
                            print(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                            
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                       
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main process of the peer
                            # if the socket that we received the data belongs to the peer that we are chatting with,
                            # enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                # prints prompt for the incoming chat request
                                print("Incoming chat request from " + self.chattingClientName + " >> ")
                                print("Enter OK to accept or REJECT to reject:  ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are chatting with
                            # and if the user is already chatting with someone else(isChatRequested = 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is 
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be shown to the peer of this server
                        elif messageReceived == "OK":
                            self.isChatRequested = 1
                            

                        # if an REJECT message is received then ischatrequested is made 0 so that it can receive any other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and 
                        # if it is not an empty message, show this message to the user
                        elif messageReceived[:2] != ":q" and len(messageReceived)!= 0 :
                            print(self.chattingClientName + ": " + messageReceived)
                        # if the message received is a quit message ':q',
                        # makes ischatrequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            self.isChatRequested = 0
                           
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(messageReceived) == 2:
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")
                       

                        
            # handles the exceptions, and logs them
            except OSError as oErr:
                print("OSError: {0}".format(oErr))
            except ValueError as vErr:
                print("ValueError: {0}".format(vErr))
            







class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False


    # main method of the peer client thread
    def run(self):
        print("Peer client started...")
        # connects to the server of other peer
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the server this client connects
            requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort)+ " " + self.username
            # logs the chat request sent to other peer
           
            # sends the chat request
            self.tcpClientSocket.send(requestMessage.encode())
            print("Request message " + requestMessage + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
          
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the connected server
            if self.responseReceived[0] == "OK":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                while self.peerServer.isChatRequested == 1:
                    # message input prompt
                    messageSent = input(self.username + ": ")
                    # sends the message to the connected peer, and logs it
                    self.tcpClientSocket.send(messageSent.encode())
                   
                    # if the quit message is sent, then the server status is changed to not chatting
                    # and this is the side that is ending the chat
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        break
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                          
                        except BrokenPipeError as bpErr:
                           print("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected peer's server
            # logs the message and then the socket is closed       
            elif self.responseReceived[0] == "REJECT":
                self.peerServer.isChatRequested = 0
                print("client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
               
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
        # if the client is created with OK message it means that this is the client of receiver side peer
        # so it sends an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == "OK":
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            okMessage = "OK"
            self.tcpClientSocket.send(okMessage.encode())
          
            print("Client with OK message is created... and sending messages")
            # client can send messsages as long as the server status is chatting
            while self.peerServer.isChatRequested == 1:
                # input prompt for user to enter message
                messageSent = input(self.username + ": ")
                self.tcpClientSocket.send(messageSent.encode())
             
                # if a quit message is sent, server status is changed
                if messageSent == ":q":
                    self.peerServer.isChatRequested = 0
                    self.isEndingChat = True
                    break
            # if server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                 
                self.responseReceived = None
                self.tcpClientSocket.close()
                






# def receive_messages(client_socket):
#     while True:
#         message = client_socket.recv(1024).decode('utf-8')
#         if not message:
#             break
        
#         print(message)




def receive_messages(sock,online_ips:list, send_stop_event,recieve_stop_event,username,port):
    
    while not recieve_stop_event.is_set():
       
        try:
            data, addr = sock.recvfrom(1024)
            decodded_data = data.decode('utf-8')
            
            if not decodded_data:
               continue
            if decodded_data==":leave":
               continue
       
        
        
        
            
            if decodded_data.startswith(":joined"):
           
               data_list = decodded_data.split()
               
                       

               if int(data_list[2])==port:
                   continue
               
               
               else:
                     
                     client_info =({
                     "client_ip": data_list[1],
                     "client_port": int(data_list[2])
               
                      })
                     if client_info not in online_ips:
                        online_ips.append(client_info)
                     continue
                     
            
            
           
            
            if decodded_data.startswith(":leaved"):
           
                data_list = decodded_data.split()

                if int(data_list[2])==port:
                   continue
                else:
                     client_to_remove = ({
                            "client_ip": data_list[1],
                          "client_port": int(data_list[2])
                                          })
                     online_ips.remove(client_to_remove)
                
                
            data_orig = decodded_data.split(":")

            random_color = random.choice([Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE])   
        #if(decodded_data==":leave"):
        #    break 
        #    send_stop_event.set()
        #    current_send_thread.join()
        #    send_stop_event.clear()
        #    send_thread = threading.Thread(target=send_messages, args=(sock,online_ips, send_stop_event,recieve_stop_event))
        #    send_thread.start()
           
            print(random_color  + f"{data_orig[1]}: {data_orig[0]}"+ Style.RESET_ALL)

        except error as e:
            print("")
            
          
        
    print("recieve thread is stoped")      


def send_messages(
    sock:socket,
    online_ips,
    send_stop_event: threading.Event,
    recieve_stop_event,
    port,
    ip,
    username,
):
    while not send_stop_event.is_set():
        message = input("You: "+ '\n')
        for user in online_ips:
            if user["client_port"] == port:
                continue
            sock.sendto(
                f"{message}:{username}".encode("utf-8"), (user["client_ip"], user["client_port"])
            )
        if message == ":leave":
            recieve_stop_event.set()
            send_stop_event.set()
            for user in online_ips:
              message = f":leaved {ip} {port}"
              sock.sendto(message.encode('utf-8'), (user['client_ip'],user['client_port'] ))

            
            break

    print("send thread is stoped")
    send_stop_event.clear()
           
        
def join_peer(ip, port, online_ips,username):
        peer_socket = socket(AF_INET, SOCK_DGRAM)
        peer_socket.bind((ip, port))

        for user in online_ips:
           message = f":joined {ip} {port}"
           peer_socket.sendto(message.encode('utf-8'), (user['client_ip'],user['client_port'] ))

        recieve_stop_event = threading.Event()
        send_stop_event = threading.Event()
        
        send_thread = threading.Thread(target=send_messages, args=(peer_socket,online_ips, send_stop_event, recieve_stop_event,port,ip,username))
        receive_thread = threading.Thread(target=receive_messages, args=(peer_socket,online_ips,send_stop_event,recieve_stop_event,username,port))
       
      
        
        receive_thread.start()
        send_thread.start()
            
        # Wait for both threads to finish
        receive_thread.join()
        
        
def start_peer(ip, port,online_ips,username):
        peer_socket = socket(AF_INET, SOCK_DGRAM)
        peer_socket.bind((ip, port))

        recieve_stop_event = threading.Event()
        send_stop_event = threading.Event()
        
        send_thread = threading.Thread(target=send_messages, args=(peer_socket,online_ips, send_stop_event, recieve_stop_event,port,ip,username))
        receive_thread = threading.Thread(target=receive_messages, args=(peer_socket,online_ips,send_stop_event,recieve_stop_event,username,port))
       



        receive_thread.start()
        send_thread.start()
            
        # Wait for both threads to finish
        receive_thread.join()
    



class main:
   

    # peer initializations
  def __init__(self):
        
    self.loginCredentials = (None, None)
        # online status of the peer
    self.isOnline = False
        # server port number of this peer
    self.peerServerPort = None
    self.peerServerip = None
        # server of this peer
    self.peerServer = None
        # client of this peer
    self.peerClient = None


    
    # Setup the client
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))
    local_ip = client_socket.getsockname()[0]
    local_port = client_socket.getsockname()[1]
    
    choice = input("Enter your choice(login/signup): ")
    client_socket.send(choice.encode('utf-8'))
    # Get username and password from the user
    if choice==":login":
       username = input("Enter username: ")
       password = maskpass.askpass(prompt="Enter Password:", mask="*")
      

       # Send username and password to the server
       client_socket.send(username.encode('utf-8'))
       client_socket.send(password.encode('utf-8'))
       # Receive authentication result
       result = client_socket.recv(1024).decode('utf-8')
       print(result)
       
       if result == "Authentication successful":
          # Start a thread to receive messages
          result2 = client_socket.recv(1024).decode('utf-8')
          print(result2)
          
          self.isOnline = True
          self.loginCredentials = (username, password)
          self.peerServerPort = local_port
          self.peerServerip = local_ip
                    # creates the server thread for this peer, and runs it
          self.peerServer = PeerServer(self.loginCredentials[0],self.peerServerip ,self.peerServerPort)
          self.peerServer.start()
         
          while True:
           
            # Allow the client to input messages or request the online clients list
            command = input("choose:"+"\n"+" 1- :search"+"\n"+" 2- :list"+"\n"+" 3- :list rooms"+"\n"+" 4- :join (room_name)"+"\n"+" 5- :create"+"\n"+" 6- :logout"+"\n"+" 7- :one_to_one"+"\n")
            
            if command.lower() == ':list':
              try:
                client_socket.send(command.encode('utf-8'))
                online_users_json = client_socket.recv(4096).decode('utf-8')
                online_users = json.loads(online_users_json)

                if online_users:
                   print("Online Users:")
                   for user in online_users:
                     print(f"Username: {user['username']}")
                   
                else:
                   print("Failed to fetch online users.")
              except json.JSONDecodeError as e:
                  print(f"Error decoding JSON: {e}")

            elif command == 'onetoone':
                
                   
                    client_socket.send(":search_user".encode('utf-8'))
                    username1 = input("Enter the username of user to start chat: ")
                    client_socket.send(username1.encode('utf-8'))
                    resp_json = client_socket.recv(1024).decode('utf-8')
                    
                    
                    if resp_json != "user is not found":
                      
                        resp =json.loads(resp_json)
                      
                      
                        self.peerClient = PeerClient(resp["client_ip"], int(resp["client_port"]) , self.loginCredentials[0], self.peerServer, None)
                        self.peerClient.start()
                        self.peerClient.join()
                    else:
                        print("user is not online")
            
            elif command == 'OK' :
                okMessage = "OK " + self.loginCredentials[0]
              
                self.peerServer.connectedPeerSocket.send(okMessage.encode())
                self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort , self.loginCredentials[0], self.peerServer, "OK")
                self.peerClient.start()
                self.peerClient.join()
            # if user rejects the chat request then reject message is sent to the requester side
            elif command == 'REJECT' :
                self.peerServer.connectedPeerSocket.send("REJECT".encode())
                self.peerServer.isChatRequested = 0
                

            elif command.lower() == ':search':
               client_socket.send(command.encode('utf-8'))
               username1 = input("Enter username: ")
               client_socket.send(username1.encode('utf-8'))
               resp = client_socket.recv(1024).decode('utf-8')
               print(resp)
                  
            elif command.lower().startswith(':join'):
                 room_list = command.split()
                 if len(room_list) != 2:
                    print("Invalid room id")
                    continue
                
                 room_id = command.split()[1]
                 client_socket.send(f"join room {room_id}".encode('utf-8'))
                
                 online_users_list_json = client_socket.recv(4096).decode('utf-8')
                 if(online_users_list_json=="Room not found."):
                     print("Invalid room id")
                     continue
                 online_ips = list(json.loads(online_users_list_json))
                 join_peer(local_ip, local_port,online_ips,username)
                 


            elif command.lower() == ':create':
                     client_socket.send("create room".encode('utf-8'))
                     room_name = input("Enter name: ")
                     client_socket.send(room_name.encode('utf-8'))
                     resp = client_socket.recv(1024).decode('utf-8')
                     print(resp)
                     online_users_list_json = client_socket.recv(4096).decode('utf-8')
                     online_ips = list(json.loads(online_users_list_json))    #online_ips[0]['client_ip']
                     
                     start_peer(local_ip, local_port,online_ips,username)
                     
            elif command.lower() == ':list rooms':
                try:
                  client_socket.send(command.encode('utf-8'))
                  online_rooms_json = client_socket.recv(4096).decode('utf-8')
                  online_rooms = json.loads(online_rooms_json)

                  if online_rooms:
                     print("Available Rooms:")
                     for room in online_rooms:
                       print(f"Room_name: {room['Room_name']}")
                   
                  else:
                      print("there is no available rooms.")
                      
                except json.JSONDecodeError as e:
                  print(f"Error decoding JSON: {e}")
                        
                              
               
                   
            elif command.lower() == ':logout':
                    client_socket.send(":logout".encode('utf-8'))
                    break
            else:
               print("invalid command")
    
    elif choice==":signup":
        username = input("Enter new username: ")
        password = maskpass.askpass(prompt="Enter Password:", mask="*")
       
        client_socket.send(username.encode('utf-8'))
       
        client_socket.send(password.encode('utf-8'))
        result = client_socket.recv(1024).decode('utf-8')
        print(result)
        if result == "user is register successfully":
            # receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
            # receive_thread.start()
         
         result2 = client_socket.recv(1024).decode('utf-8')
         print(result2)
          
         self.isOnline = True
         self.loginCredentials = (username, password)
         self.peerServerPort = local_port
         self.peerServerip = local_ip
                    # creates the server thread for this peer, and runs it
         self.peerServer = PeerServer(self.loginCredentials[0],self.peerServerip ,self.peerServerPort)
         self.peerServer.start()
         while True:
              # Allow the client to input messages or request the online clients list
            command = input("choose:"+"\n"+" 1- :search"+"\n"+" 2- :list"+"\n"+" 3- :list rooms"+"\n"+" 4- :join (room_name)"+"\n"+" 5- :create"+"\n"+" 6- :logout"+"\n"+" 7- :one_to_one"+"\n")
            
            if command.lower() == ':list':
              try:
                client_socket.send(command.encode('utf-8'))
                online_users_json = client_socket.recv(4096).decode('utf-8')
                online_users = json.loads(online_users_json)

                if online_users:
                   print("Online Users:")
                   for user in online_users:
                     print(f"Username: {user['username']}")
                   
                else:
                   print("Failed to fetch online users.")
              except json.JSONDecodeError as e:
                  print(f"Error decoding JSON: {e}")

            elif command == 'onetoone':
                
                   
                    client_socket.send(":search_user".encode('utf-8'))
                    username1 = input("Enter the username of user to start chat: ")
                    client_socket.send(username1.encode('utf-8'))
                    resp_json = client_socket.recv(1024).decode('utf-8')
                    
                    
                    if resp_json != "user is not found":
                      
                        resp =json.loads(resp_json)
                        
                        
                        self.peerClient = PeerClient(resp["client_ip"], int(resp["client_port"]) , self.loginCredentials[0], self.peerServer, None)
                        self.peerClient.start()
                        self.peerClient.join()
                    else:
                        print("user is not online")
            
            elif command == 'OK' :
                okMessage = "OK " + self.loginCredentials[0]
              
                self.peerServer.connectedPeerSocket.send(okMessage.encode())
                self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort , self.loginCredentials[0], self.peerServer, "OK")
                self.peerClient.start()
                self.peerClient.join()
            # if user rejects the chat request then reject message is sent to the requester side
            elif command == 'REJECT' :
                self.peerServer.connectedPeerSocket.send("REJECT".encode())
                self.peerServer.isChatRequested = 0
                

            elif command.lower() == ':search':
               client_socket.send(command.encode('utf-8'))
               username1 = input("Enter username: ")
               client_socket.send(username1.encode('utf-8'))
               resp = client_socket.recv(1024).decode('utf-8')
               print(resp)
                  
            elif command.lower().startswith(':join'):
                 room_list = command.split()
                 if len(room_list) != 2:
                    print("Invalid room id")
                    continue
                
                 room_id = command.split()[1]
                 client_socket.send(f"join room {room_id}".encode('utf-8'))
                
                 online_users_list_json = client_socket.recv(4096).decode('utf-8')
                 if(online_users_list_json=="Room not found."):
                     print("Invalid room id")
                     continue
                 online_ips = list(json.loads(online_users_list_json))
                 join_peer(local_ip, local_port,online_ips,username)
                 


            elif command.lower() == ':create':
                     client_socket.send("create room".encode('utf-8'))
                     room_name = input("Enter name: ")
                     client_socket.send(room_name.encode('utf-8'))
                     resp = client_socket.recv(1024).decode('utf-8')
                     print(resp)
                     online_users_list_json = client_socket.recv(4096).decode('utf-8')
                     online_ips = list(json.loads(online_users_list_json))    #online_ips[0]['client_ip']
                     
                     start_peer(local_ip, local_port,online_ips,username)
                     
            elif command.lower() == ':list rooms':
                try:
                  client_socket.send(command.encode('utf-8'))
                  online_rooms_json = client_socket.recv(4096).decode('utf-8')
                  online_rooms = json.loads(online_rooms_json)

                  if online_rooms:
                     print("Available Rooms:")
                     for room in online_rooms:
                       print(f"Room_name: {room['Room_name']}")
                   
                  else:
                      print("there is no available rooms.")
                      
                except json.JSONDecodeError as e:
                  print(f"Error decoding JSON: {e}")
                        
                              
               
                   
            elif command.lower() == ':logout':
                    client_socket.send(":logout".encode('utf-8'))
                    break
            else:
               print("invalid command")
    else:
        print("error,enter correct choice")
    
    
    client_socket.close
    
   
        
main = main()