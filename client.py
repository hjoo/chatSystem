"""
Chat room client

Author: Hyonjee Joo

Usage: python client.py ip_address port_number
"""

import sys
import socket
import select
import threading
import thread 
import signal
import time
import packet

HEARTBEAT_TIME = 30 # seconds, should be less than timeout value set in server
log_in_successful = False
server_responded = threading.Condition()
this_port = 0
listening_port_status = threading.Condition()
private_address = {} # key = user, value = (ip, port)

"""
Sets up client's listening post and handles responses from Server or
private messager.
"""
class IncomingHandlerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.host = ''
        self.buff_size = 4096

    def create_listening_socket(self):
        try:
            listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listening_sock.bind((self.host, 0))
            global this_port
            this_port = listening_sock.getsockname()[1]
            # notify client that listening port set up
            listening_port_status.acquire()
            listening_port_status.notify()
            listening_port_status.release()

            listening_sock.listen(5)
            return listening_sock
        except socket.error, (err, message):
            print "Unable to open listening socket. Error: " + message
            sys.exit(1)

    # perform action indidcated by server
    def interpret_server_response(self, command, pkt_from_server):
        if command == "log_in":
            if pkt_from_server.get_field("status") == "success":
                global log_in_successful
                log_in_successful = True
                print (">Welcome to the chat system!")
            elif pkt_from_server.get_field("status") == "fail":
                print (">Invalid password. Please try again.")
            elif pkt_from_server.get_field("status") == "not_user":
                print (">Not a valid user.")
                thread.interrupt_main()
            elif pkt_from_server.get_field("status") == "fail_and_locked":
                print (">Invalid password. Your account has been blocked. " \
                        "Please try again after some time.")
                thread.interrupt_main()
            else:
                print (">Due to multiple log in failures, your account has " \
                        "been blocked. Please try again after some time.")
                thread.interrupt_main()
        elif command == "getaddress":
            if pkt_from_server.get_field("status") == "success":
                ip = pkt_from_server.get_field("ip") 
                port = pkt_from_server.get_field("port") 
                user = pkt_from_server.get_field("user")
                global private_address
                private_address[user] = (ip, int(port))
                sys.stdout.write("User " + user + " ip: " + ip + ", port: " \
                        + port + "\n>")
                sys.stdout.flush()
        elif command == "consent":
                user = pkt_from_server.get_field("asking_user")
                sys.stdout.write("User " + user + " is asking for consent.\n>")
                sys.stdout.write("To ignore, do nothing. To give consent, " + \
                        "enter: consent <user>\n>")
                sys.stdout.flush()
        elif command == "update_private_list":
            old_user = pkt_from_server.get_field("old_user") 
            if old_user in private_address:
                del private_address[old_user]
                sys.stdout.write("User " + old_user + " changed IP addresses. " + \
                        "Ask for address again.\n>")
                sys.stdout.flush()
        elif command == "end_user_for_this_ip":
            print ("User logged in from new IP. Press Enter or CTRL-c to exit.")
            thread.interrupt_main()
        elif command == "disconnected":
            print ("TIMEOUT: disconnected by server. Press Enter or CTRL-c" \
                    " to exit.")
            thread.interrupt_main()
        elif command == "server_shutdown":
            print ("Server is shutting down. Press Enter or CTRL-c to exit.")
            thread.interrupt_main()
        else:
            sys.stdout.write("Unknown server command.\n>")
            sys.stdout.flush()
        
    def run(self):
        listener = self.create_listening_socket()
        while 1:
            # client is listening
            connected_socket, address = listener.accept()
            data = connected_socket.recv(self.buff_size)
            if data:
                response_pkt = packet.Packet()
                response_pkt.parse(data)
                # interpret server's response
                if response_pkt.get_field("cmd"):
                    server_command = response_pkt.get_field("cmd")
                    self.interpret_server_response(server_command, response_pkt)
                # or print message for user
                elif response_pkt.get_field("type") == "system":
                    sys.stdout.write(response_pkt.get_field("message") + "\n>")
                    sys.stdout.flush()
                else: 
                    sys.stdout.write(response_pkt.sender + ": " + \
                            response_pkt.get_field("message") + "\n>")
                    sys.stdout.flush()
                # notify client that server response received
                server_responded.acquire()
                server_responded.notify() 
                server_responded.release()
            connected_socket.close()
        listener.close()

"""
Thread to send heartbeat to server every HEARTBEAT_TIME seconds.
"""
class HeartbeatThread(threading.Thread):
    def __init__(self, server_host, server_port, heartbeat_pkt, time):
        threading.Thread.__init__(self)
        self.s_host = server_host
        self.s_port = server_port
        self.pkt = heartbeat_pkt
        self.interval = time

    def run(self):
        while 1:
            send_to_server(self.s_host, self.s_port, self.pkt)
            time.sleep(self.interval) 

"""
Helper method for sending packet to server.
"""
def send_to_server(host, port, pkt):
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s_sock.connect((host, port))
        s_sock.send(pkt.to_string())
        s_sock.close()
    except socket.error, (err, message):
        sys.stderr.write("Server is down.")
        sys.exit(1)

"""
Helper method for sending packet directly to another user.
"""
def private_send(pkt):
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_user = pkt.get_field("to")
    if target_user in private_address:
        try:
            s_sock.connect(private_address[target_user])
            s_sock.send(pkt.to_string())
            s_sock.close()
        except socket.error, (err, message):
            sys.stderr.write(">User " + target_user + " is no longer available " + \
                    "at " + str(private_address[target_user]) + ". You can " + \
                    "send an offline message through the server.\n")
    else:
        sys.stderr.write(">Please request user address first (getaddress <user>).\n")

"""
Parses user input into packet to send to server. Return None if error.
"""
def make_packet(sender_host, sender_port, sender_name, user_input):
    pkt = packet.Packet(this_host, this_port, sender_name) 
    try:
        command_words = user_input.strip().split(" ") 
        command = command_words[0].lower()
        if command == "message":
            pkt.create_msg("public", " ".join(command_words[2:]), command_words[1])
        elif command == "broadcast":
            pkt.create_msg("broadcast", " ".join(command_words[1:]), "all")
        elif command == "private":
            pkt.create_msg("private", " ".join(command_words[2:]), command_words[1])
        elif command == "block":
            pkt.add_fields([("cmd", "block"),("target", command_words[1])])
        elif command == "unblock":
            pkt.add_fields([("cmd", "unblock"),("target", command_words[1])])
        elif command == "online":
            pkt.add_fields([("cmd", "online")])
        elif command == "logout":
            pkt.add_fields([("cmd", "logout")])
        elif command == "getaddress":
            pkt.add_fields([("cmd", "getaddress"),("target", command_words[1])])
        elif command == "consent":
            pkt.add_fields([("cmd", "consent"),("user", command_words[1])])
        else:
            return None
        return pkt
    except:
        return None

def signal_handler(signal, frame): 
    print ("\n>Client is terminating. Bye!")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: python client.py ip_address port_number\n")
        sys.exit(1)
    server_host = sys.argv[1]
    server_port = int(sys.argv[2])
    this_host = socket.gethostbyname(socket.gethostname())

    # set up keyboard interrupt signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # set up listening post for incoming server or private messgaes
    listener = IncomingHandlerThread()
    listener.setDaemon(True)
    listener.start()

    # wait until IncomingHandlerThread sets up open port
    listening_port_status.acquire()
    listening_port_status.wait()
    listening_port_status.release()

    user = raw_input(">Username: ")
    user = "".join(user.split()) # username cannot have spaces
    # prompt log in until server indicates success and acknowledges user
    while not log_in_successful:
        password = raw_input(">Password: ")
        log_in_request = packet.Packet(this_host, this_port, user)
        log_in_request.add_fields([("cmd", "log_in"),("password", password)])
        send_to_server(server_host, server_port, log_in_request)
        # wait for server response
        server_responded.acquire()
        server_responded.wait()
        server_responded.release()

    # only reaches this point if log in successful
    # start heartbeats
    heartbeat_pkt = packet.Packet(this_host, this_port, user)
    heartbeat_pkt.add_fields([("cmd", "heartbeat")])
    heartbeat = HeartbeatThread(server_host, server_port, heartbeat_pkt, HEARTBEAT_TIME)
    heartbeat.setDaemon(True)
    heartbeat.start()

    while 1:
        sys.stdout.write(">")
        sys.stdout.flush()
        select.select([sys.stdin], [], [])
        user_input = sys.stdin.readline()
        if user_input == '\n': # user did not type anything, just hit Enter
            continue
        pkt = make_packet(this_host, this_port, user, user_input)
        # if packet successfully created, send to private user or server
        if pkt is not None:
            if pkt.get_field("type") == "private":
                private_send(pkt)
            else: 
                send_to_server(server_host, server_port, pkt)
                # if logout packet then terminate client
                if pkt.get_field("cmd") == "logout":
                    print ">Logging out. Bye for now!"
                    sys.exit(1)
        else:
            print ">Bad input. Try again."
