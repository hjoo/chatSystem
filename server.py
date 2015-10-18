"""
Message Center server. 

Author: Hyonjee Joo

Usage: python server.py port_number
"""

import sys
import signal
import socket
import Queue
import threading
import packet
import time
from collections import defaultdict
from datetime import datetime, timedelta

READ = 0
WRITE = 1
BLOCK_TIME = 60 # seconds, for log in
TIMEOUT = 35 # seconds, should be less than client HEARTBEAT_TIME 
# incoming packets are placed in a queue for the controller to process
pkt_queue = Queue.Queue(16)
queue_lock = threading.Lock()
controller_running = True
controller_done = threading.Condition()

"""
Thread to read from and write to accepted client connection.
"""
class ClientThread(threading.Thread):
    def __init__(self, (client_sock, address), read_or_write, response=None):
        threading.Thread.__init__(self)
        self.client_sock = client_sock
        self.address = address 
        self.buff_size = 4096
        self.operation = read_or_write
        self.response = response 

    def run(self):
        if self.operation == READ:
            # read data from client in 4096 buffer size chunks
            data = self.client_sock.recv(self.buff_size)
            while data:
                p = packet.Packet()
                p.parse(data)

                # putting received packet into queue
                global pkt_queue, queue_lock
                queue_lock.acquire()
                pkt_queue.put(p)
                queue_lock.release()

                data = self.client_sock.recv(self.buff_size)
        elif self.operation == WRITE:
            # send data to client
            sent = self.client_sock.send(self.response)
            if not sent == len(self.response):
                sys.stderr.write("socket send failed")
        self.client_sock.close()

"""
Authenticator manages username/password database, maintains states for number
of failed attempts and lockout times.
"""
class Authenticator(object):
    def __init__(self, log_in_database):
        # username/password database
        self.log_in_database = log_in_database
        self.failed_attempts = defaultdict(int)
        self.lockout_times = {}

    def is_user(self, username):
        if username in self.log_in_database:
            return True
        return False

    def check_if_failed_third_try(self, username):
        if self.failed_attempts[username] == 3:
            return True
        return False

    def is_locked(self, username):
        if self.failed_attempts[username] < 3:
            return False
        elif (datetime.utcnow() > self.lockout_times[username] 
                + timedelta(seconds=BLOCK_TIME)):
            # enough time has passed, reset number of attempts to 0
            self.failed_attempts[username] = 0
            return False
        else:
            return True

    def is_valid(self, username, password):
        if self.is_user(username):
            if not self.is_locked(username):
                if self.log_in_database[username] == password:
                    self.failed_attempts[username] = 0
                    return True
                else:
                    self.failed_attempts[username] += 1
                    if self.check_if_failed_third_try(username):
                        self.lockout_times[username] = datetime.utcnow()
                    return False
            else:
                return False
        else:
            return False
        
"""
Manages user blacklists providing functions to update and check block settings.
"""
class Blacklist(object):
    def __init__(self):
        self.blacklist = defaultdict(set) # key=user, value=blacklist
    
    def is_listed(self, sender_user, list_owner):
        if sender_user in self.blacklist[list_owner]:
            return True
        return False

    def block(self, blocked_user, list_owner):
        self.blacklist[list_owner].add(blocked_user)

    def unblock(self, unblocked_user, list_owner):
        if unblocked_user in self.blacklist[list_owner]:
            self.blacklist[list_owner].remove(unblocked_user)

    def get_blockers(self, sender_user):
        blocking_users = set()
        for list_owner in self.blacklist:
            if sender_user in self.blacklist[list_owner]:
                blocking_users.add(list_owner)
        return blocking_users

    def get_list(self, list_owner):
        return self.blacklist[list_owner]

"""
Controller gets packet from queue, performs appropriate action, and generates
response. Contains core logic for message center.
"""
class Controller(threading.Thread):
    def __init__(self, server_port, authenticator):
        threading.Thread.__init__(self)
        self.server_host = socket.gethostbyname(socket.gethostname())
        self.server_port = server_port
        self.auth = authenticator
        self.blacklist = Blacklist()
        self.heartbeats = {} # key = user, value = last_heartbeat_time
        self.saved_msgs = defaultdict(list) # key = receiving_user, value = msg_list
        self.asked_consent = defaultdict(set) # key = asking_user, value = inquiries
        self.users = {} # key = user, value = address

    # send response packet (in string form) to all addresses in list
    def send_response(self, address_list, response_p):
        for address in address_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(address) 
                sender = ClientThread((sock, address), WRITE, response_p.to_string())
                sender.setDaemon(True)
                sender.start()
            except: 
                # if send failed for msg, alert sender and log
                # guarantee message delivery
                if response_p.is_msg and response_p.sender != "server":
                    source_addr = (response_p.sender_host, \
                            int(response_p.sender_port))
                    notify_pkt = packet.Packet(self.server_host, self.server_port, \
                            "server")
                    notify_pkt.create_msg("system", "Message to " + 
                            response_p.get_field("to") + " failed. Recontact the" + 
                            " server after the user has timed out to leave an " + 
                            "offline message.", response_p.sender)
                    self.send_response([source_addr], notify_pkt) 
                print "send to " + str(address)+ " failed."
                pass # do nothing else if send failed

    def log_off_old_user(self, old_user):
        log_off_pkt = packet.Packet(self.server_host, self.server_port, "server")
        log_off_pkt.add_fields([("cmd", "end_user_for_this_ip")])
        self.send_response([self.users[old_user]], log_off_pkt)
        del self.users[old_user]
        # also let private message clients know
        notify_pkt = packet.Packet(self.server_host, self.server_port, "server")
        notify_pkt.add_fields([("cmd", "update_private_list"), \
                ("old_user", old_user)])
        self.send_response(self.users.values(), notify_pkt)

    def presence_broadcast(self, logon_or_logout, user):
            presence_pkt = packet.Packet(self.server_host, self.server_port, "server")
            if logon_or_logout == "log_on":
                presence_pkt.create_msg("system", "User " + user + " has " + \
                        "logged on.", "many_users") 
            else:
                presence_pkt.create_msg("system", "User " + user + " has " + \
                        "logged off.", "many_users") 
            user_set = (set(self.users.keys())).difference({user})
            broadcast_set = user_set.difference(self.blacklist.get_list(user))
            addresses = [self.users[x] for x in broadcast_set]
            self.send_response(addresses, presence_pkt)

    def run_log_in(self, pkt):
        return_pkt = packet.Packet(self.server_host, self.server_port, "server")
        if not self.auth.is_user(pkt.sender):
            return_pkt.add_fields([("cmd", "log_in"),("status", "not_user")])
        elif self.auth.is_locked(pkt.sender):
            return_pkt.add_fields([("cmd", "log_in"),("status", "locked")])
        elif self.auth.is_valid(pkt.sender, pkt.get_field("password")):
            return_pkt.add_fields([("cmd", "log_in"),("status", "success")])
            # log off new user from other ips
            if pkt.sender in self.users:
                if self.users[pkt.sender] != pkt.get_sender_addr():
                    self.log_off_old_user(pkt.sender)
            # add user and current ip to user database
            self.users[pkt.sender] = pkt.get_sender_addr()
        elif self.auth.check_if_failed_third_try(pkt.sender):
            return_pkt.add_fields([("cmd", "log_in"),("status", "fail_and_locked")])
        else:
            return_pkt.add_fields([("cmd", "log_in"),("status", "fail")])
        self.send_response([pkt.get_sender_addr()], return_pkt)
        # if successful log in, broadcast and send any stored messages
        if return_pkt.get_field("status") == "success":
            self.presence_broadcast("log_on", pkt.sender) 
            # forward saved messages
            for saved_pkt in self.saved_msgs[pkt.sender]:
                self.run_message(saved_pkt)
            del self.saved_msgs[pkt.sender][:]

    def run_block(self, pkt):
        self.blacklist.block(pkt.get_field("target"), pkt.sender)
        return_pkt = packet.Packet(self.server_host, self.server_port, "server")
        return_pkt.create_msg("system", "User " + pkt.get_field("target") + \
                " has been blocked.", pkt.sender)
        self.send_response([pkt.get_sender_addr()], return_pkt)

    def run_unblock(self, pkt):
        self.blacklist.unblock(pkt.get_field("target"), pkt.sender)
        return_pkt = packet.Packet(self.server_host, self.server_port, "server")
        return_pkt.create_msg("system", "User " + pkt.get_field("target") + \
                " has been unblocked.", pkt.sender)
        self.send_response([pkt.get_sender_addr()], return_pkt)

    def run_show_online(self, pkt):
        online_set = (set(self.users.keys())).difference({pkt.sender})
        visible_set = online_set.difference(self.blacklist.get_blockers(pkt.sender))
        message = ""
        for user in visible_set:
            message += user + "\n>"
        message += "(Warning: Users that have blocked you will not be listed)"
        return_pkt = packet.Packet(self.server_host, self.server_port, "server")
        return_pkt.create_msg("system", message, pkt.sender)
        self.send_response([pkt.get_sender_addr()], return_pkt)

    def run_heartbeat_log(self, pkt):
        # heartbeat only registered for logged in users
        if pkt.sender in self.users:
            self.heartbeats[pkt.sender] = datetime.utcnow()
            print "LIVE signal from " + pkt.sender + " (" + pkt.sender_host + ")"
        
    def run_logout(self, pkt):
        self.presence_broadcast("logout", pkt.sender)
        del self.users[pkt.sender]
        del self.heartbeats[pkt.sender]
        print "User " + pkt.sender + " logged off."

    def run_ask_consent(self, pkt):
        consent_asked = False
        consent_pkt = packet.Packet(self.server_host, self.server_port, "server")
        consent_pkt.add_fields([("cmd", "consent"), ("asking_user", pkt.sender)])
        return_pkt = packet.Packet(self.server_host, self.server_port, "server")
        inquired_user = pkt.get_field("target")
        if inquired_user in self.users:
            # if user is blocked, can't ask for consent
            if not self.blacklist.is_listed(pkt.sender, inquired_user):
                self.send_response([self.users[inquired_user]], consent_pkt)
                return_pkt.create_msg("system", "consent asked from User " + \
                        inquired_user + ".", pkt.sender)
                self.asked_consent[pkt.sender].add(inquired_user)
                consent_asked = True
        if not consent_asked: 
            return_pkt.create_msg("system", "getaddress request for " + \
                    inquired_user + " failed.", pkt.sender)
        self.send_response([self.users[pkt.sender]], return_pkt)
        
    def run_give_consent(self, pkt):
        if pkt.sender in self.asked_consent[pkt.get_field("user")]:
            return_pkt = packet.Packet(self.server_host, self.server_port, "server")
            fields = [("cmd", "getaddress"), ("user", pkt.sender)]
            if pkt.sender in self.users:
                if not self.blacklist.is_listed(pkt.get_field("user"), pkt.sender):  
                    ip, port = self.users[pkt.sender]
                    fields.extend([("ip", ip),("port",str(port)),("status","success")])
                    return_pkt.add_fields(fields)
                    self.send_response([self.users[pkt.get_field("user")]], \
                            return_pkt)
            if len(fields) == 2:
                return_pkt.create_msg("system", "You blocked User " + \
                        pkt.get_field("user") + ". Unblock before giving" + \
                        " consent.", pkt.sender)
                self.send_response([self.users[pkt.sender]], return_pkt)

    def run_message(self, pkt):
        return_pkt = packet.Packet(pkt.sender_host, pkt.sender_port, pkt.sender)
        msg_type = pkt.get_field("type")
        recipient = pkt.get_field("to")
        if msg_type == "public" and self.auth.is_user(recipient):
            if self.blacklist.is_listed(pkt.sender, recipient):  
                return_pkt.create_msg("system", "Your message could not be" + \
                        " delivered as the recipient has blocked you.", pkt.sender)
                self.send_response([self.users[pkt.sender]], return_pkt)
            else:
                if recipient in self.users:
                    return_pkt.create_msg("public", pkt.get_field("message"), \
                            recipient)
                    self.send_response([self.users[recipient]], return_pkt)
                else:
                    self.saved_msgs[recipient].append(pkt)
        elif msg_type == "broadcast":
            user_set = (set(self.users.keys())).difference({pkt.sender})
            broadcast_set = user_set.difference(self.blacklist.get_blockers(pkt.sender))
            if len(user_set) is not len(broadcast_set):
                alert_pkt = packet.Packet(self.server_host, self.server_port, "server")
                alert_pkt.create_msg("system", "Your message could not be" + \
                        " delivered to some recipients.", pkt.sender)
                self.send_response([self.users[pkt.sender]], alert_pkt)
            return_pkt.create_msg("broadcast", pkt.get_field("message"))
            for user in broadcast_set:
                return_pkt.add_fields([("to", user)])
                address = self.users[user]
                self.send_response([address], return_pkt)

    # pick and run appropriate controller command
    def respond(self, pkt):
        command = pkt.get_field("cmd")
        if command:
            if command == "log_in":  
                self.run_log_in(pkt)
            elif command == "block":
                self.run_block(pkt)
            elif command == "unblock":
                self.run_unblock(pkt)
            elif command == "online":
                self.run_show_online(pkt)
            elif command == "heartbeat":
                self.run_heartbeat_log(pkt)
            elif command == "logout":
                self.run_logout(pkt)
            elif command == "getaddress":
                self.run_ask_consent(pkt)
            elif command == "consent":
                self.run_give_consent(pkt)
        else:
            self.run_message(pkt)

    # clean up users that have timed out or logged off
    def update_user_list(self):
        disconnected_users = []
        for user in self.heartbeats:
            if (datetime.utcnow() > self.heartbeats[user] +
                    timedelta(seconds=TIMEOUT)):
                disconnected_users.append(user)
        for xuser in disconnected_users:
            print ("TIMEOUT: User " + xuser + " disconnected.")
            del self.users[xuser]
            del self.heartbeats[xuser]
        
    def run(self):
        global pkt_queue, queue_lock
        while controller_running:
            pkt = None
            # check if queue has packets to process
            queue_lock.acquire()
            if not pkt_queue.empty():
                # grab pending packets
                pkt = pkt_queue.get()
            queue_lock.release()
            if pkt:
                self.respond(pkt)
            # enforce timeout for users
            self.update_user_list()
        # controller telling clients that server is shutting down
        shutdown_pkt = packet.Packet(self.server_host, self.server_port, "server")
        shutdown_pkt.add_fields([("cmd", "server_shutdown")])
        self.send_response(self.users.values(), shutdown_pkt)
        controller_done.acquire()
        controller_done.notify()
        controller_done.release()

"""
MessageCenter is the hub of the chat system. It creates the server socket and
listens for and accepts incoming client connections.
The MessageCenter starts a ClientThread to handle accepted client connections
so that it can continue to listen for more clients wishing to use the chat
service.
"""
class MessageCenter:
    def __init__(self, port, authenticator):
        self.host = '' # socket for all available interfaces
        self.port = port
        self.receiving_threads = []
        self.listening = True
        self.controller = Controller(port, authenticator)
        self.controller.setDaemon(True)

    def create_server_socket(self):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5) # 5 is the max number of queued connections
            return server_sock
        except socket.error, (err, message):
            print "Unable to open server socket. Error: " + message
            sys.exit(1)

    def run(self):
        self.controller.start()
        server = self.create_server_socket()
        while self.listening:
            connected_socket, address = server.accept()
            # starts new ClientThread to handle accepted clients
            receiver = ClientThread((connected_socket, address), READ)
            receiver.setDaemon(True)
            receiver.start()
            self.receiving_threads.append(receiver)

        server.close()

    def shutdown(self):
        self.listening = False
        print "\nNotifying clients of server shutdown..."
        # tell controller to stop running 
        global controller_running
        controller_running = False
        # wait until controller is finished broadcasting shutdown to clients
        controller_done.acquire()
        controller_done.wait()
        controller_done.release() 

def signal_handler(signal, frame):
    MC.shutdown()
    print ("Server is shutting down.")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python server.py port_number\n")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    signal.signal(signal.SIGINT, signal_handler)

    # fill username/password database
    log_in_database = {}
    with open('credentials.txt', 'r') as user_file:
        entries = user_file.readlines()
        for entry in entries:
            user, password = entry.strip().split(" ")
            log_in_database[user] = password
    auth = Authenticator(log_in_database)

    # start Message Center on specified port
    MC = MessageCenter(listen_port, auth)
    MC.run()
