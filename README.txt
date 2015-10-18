This is a chat system that allows for live chatting as well as saved and
forwarded messages for offline users.

How to run chat system:

1. start server
    $python server.py port_number
2. start client(s)
    $python client.py server_ip server_port

* Important note:
    - credentials.txt file must be in same directory as server.py
    - HEARTBEAT_TIME in clienty.py and TIMEOUT in server.py can be configured
        - TIMEOUT should be less than the HEARTBEAT_TIME
    - BLOCK_TIME in server.py can be configured to lockout users that have
      too many failed log in attempts
    - usernames cannot have spaces
    - this chat system has P2P Privacy & Consent, and Guaranteed Message Delivery
===============================================================================
Sample commands and examples:

* (login when client first starts)
    - broadcasted to other online users

    User A                      User B                  User C
    ($python client.py...)
    >Username: A
    >Password: A_pwd
    >Welcome to the chat 
     system!                    
                                ($python client.py...)
                                >Username: B
                                >Password: B_pwd
                                >Welcome to the chat
                                 System!
    >User B has logged on.
                                                        ($python client.py...)
                                                        >Username: C
                                                        >Password: C_pwd
                                                        >Welcome to the chat
                                                         system!
    >User C has logged on.      >User C has logged on.
    ------------------------    ----------------------  ----------------------
* message <user> <message>
    - if user not online, messages will be saved for offline delivery

    User A                      User B                  User C
    >message B hi there!
                                >A: hi there!
                                                        >message B it's user C.
                                >C: it's user C. 
    >logout
    >Logging out. Bye for now!
                                >A: hi there!

    ($python client.py...)
    >Username: A
    >Password: A_pwd
    >Welcome to the chat 
     system!
    >B: hi there!               >User A has logged on.  >User A has logged on.
                                
    ------------------------    ----------------------  ----------------------
* broadcast <message>
    - not stored for offline delivery

    User A                      User B                  User C
    >broadcast hello all
                                >A: hello all           >C: hello all
    ------------------------    ----------------------  ----------------------
* online
    - lists online users
    - does not list users that have blocked you

    User A                      User B                  User C
                                >online
                                >A
                                >C
                                >(Warning: Users that 
                                 have blocked you will 
                                 not be listed)
    ------------------------    ----------------------  ----------------------
* block <user>
    -blocking is one way. If A blocks B and C, A can still message B and C.

    User A                      User B                  User C
    >block B
    >User B has been blocked.
    >block C
    >User C has been blocked.
                                >message A hi
                                >Your message could not
                                 be delivered as the
                                 recipient has blocked
                                 you.
                                                        >broadcast hello all
                                                        >Your message could not
                                                         be received by some
                                                         recipients.
                                >C: hello all
    >message B don't reply
                                >A: don't reply
    >broadcast A don't reply
                                >A: don't reply         >A: don't reply
    ------------------------    ----------------------  ----------------------
* unblock <user>
    User A                      User B                  User C
    >unblock B
    >User B has been unblocked.
                                >message A hi
    >B: hi
    >unblock C
    >User C has been unblocked.
                                                        >broadcast hello all
    >C: hello all               >C: hello all
    ------------------------    ----------------------  ----------------------
* getaddress <user>
* consent <user>
    *** Privacy and Consent Feature ***
    - getaddress <user> asks the user for consent
    - once a user grants consent with "consent <user>", the requesting user
      will get the address for Peer to Peer communication

    User A                      User B                  User C
                                >getaddress A
                                >consent asked from User 
                                 B. 
    >User B is asking for
     consent.
    >To ignore, do nothing. To
     give consent, enter:
     consent <user>
    >consent B                  
                                >User A ip: 129.35.26.1,
                                 port: 51791
                                                        >block B
                                                        >User B has been blocked.
                                >getaddress C
                                >getaddress request for
                                 C failed.
    ------------------------    ----------------------  ----------------------
* private <user> <message> 
    - Peer to peer communication directly between clients.

    User A                      User B                  User C
                                                        >private B hi there
                                                        >Please request user
                                                         address first (getaddress
                                                         <user>). 
                                >private A hello
    >B: hello
    >^C
    >Client is terminating.Bye!
                                >private A hello again
                                >User A is no longer 
                                 available at ('129.35.
                                 26.1', 51791). You can
                                 send an offline message
                                 through the server.

    ------------------------    ----------------------  ----------------------
* logout
    - broadcasted to online users that are not blocked
    - CTRL-C is not broadcasted
    - logout terminates clienty program

    (~ User B has been blocked by User C ~)
    User A                      User B                  User C
                                                        >logout
                                                        >Logging out. Bye for now!
    >User C has logged out.

===============================================================================
Bonus Features:

Privacy and Consent - users that have been blacklisted cannot getaddress (the 
    request fails). Users must wait for inquired user to give consent.
    Command to give consent: consent <user>.
    An example can be seen above under getaddress.

Guaranteed Message Delivery - works for regular messaging, broadcasting, and
    private messaging.
    Sending user needs to wait until the disconnected user has timed out to
    send an offline message.

    Example output:
    User A                      User B                  User C
    >^C
    >Client is terminating.Bye!

                (~ User A has not yet timed out in server ~)
                                >message A hi
                                >Message to A failed.
                                 Recontact server after
                                 user has timed out to 
                                 leave an offline 
                                 message.
                                                        >broadcast hi all
                                >C: hi all              >Message to A failed. 
                                                         Recontact server after
                                                         user has timed out to 
                                                         leave an offline 
                                                         message.

                (~ User A logs in with a different IP ~)
    ($python client.py...)
    >Username: A
    >Password: A_pwd
    >Welcome to the chat        
     system!                    >User A has changed IP
                                 addresses. Ask for the 
                                 address again.
===============================================================================
Graceful exit with CTRL-C:
    
* CTRL-C from server:
    ^C
    Notifying clients of server shutdown...
    Server is shutting down.

    Client sees this message:
        >Server is shutting down. Press Enter or CTRL-c to exit.

        >Client is terminating. Bye!

* CTRL-C from client:
    >^C
    >Client is terminating. Bye!
    
    Client will eventually timeout in server.
===============================================================================
Design and Code:

The chat system is implemented with a server program (server.py), client 
programs (client.py), and a shared packet data structure (packet.py). The 3
parts are described below:

server.py
--------------
* BLOCK_TIME (for log in lockouts) and TIMEOUT (for disconnected clients) can 
  be configured.

* main method - reads in credentials.txt (which is assumed to be in the same 
  directory) and creates a database of users. It initializes an Authenticator
  with this database, and passes the Authenticator and port number to the newly
  created Message Center. The server is started by running the Message Center.
  Signal handler for CTRL-C graceful exit is also set here.

* MessageCenter - the hub of the chat system. It creates the server socket and
  listens for and accepts incoming client connections. The MessageCenter 
  starts a new ClientThread to handle each accepted client connection so that 
  it can continue to listen for more clients wishing to use the chat service.
  The MessageCenter also starts a Controller thread that handles all incoming 
  messages from clients. The shutdown method is invoked by the signal handler
  to shut down the chat server. Condition variable waits for Controller thread
  to finish cleaning up (i.e. telling clients server is shutting down).

* ClientThread - Thread to read from and write to accepted client connection.
  When ClientThread receives and reads input from a client, it parses the
  string into a packet object and places the packet on a global queue. 
  Queue is protected by lock.

* Authenticator - Authenticator manages username/password database, maintains 
  states for number of failed attempts and lockout times.

* Blacklist - Manages user blacklists providing functions to update and check 
  block settings.

* Controller - gets packet from queue, performs appropriate action, and 
  generates response. Contains core logic for message center.
    - run - continuously checks for packets in packet queue. If queue is not 
        empty, grab a packet, and process it. Also continuously checks for 
        heartbeat times and updates online status of users.
    - respond - invokes appropriate command specified in pakcet.
    - various run methods (i.e. run_log_in, run_message, etc.) - each run 
        method has logic to properly process the command and create a return
        packet if necessary.
    - send_response - start ClientThread to send response to original sender 
        or target recipient. If send failed, exception is caught and handled.
        This is important to guarantee message delivery.
  The controller maintains the state of users (ip, online status), blacklists,
  heartbeats, and which users have asked for consent (P2P Privacy and Consent).
  The controller also saves messages to forward to users once they log back on.    

* The server DOES NOT maintain state between different instances of the program.

client.py
--------------
* main method - starts IncomingHandlerThread to listen for incoming messages. 
  Waits for the IncomingHandlerThread to finish setting up listening port 
  before proceeding by waitin on a condition variable. Loops until log in 
  successful (waits for server response before looping again - may be locked
  out). Username is only asked for once. Passwords may be entered again if 
  necessary. After successful log in, heartbeat is started. Gets user input
  with select.select(), forms packet, and sends packet to server or directly
  to another user for private messages.  

* signal handler - graceful exit with CTRL-C. Does not inform server! Server
  will know user is no longer online when it does not receive a heartbeat and
  the user times out. Users should exit with "logout" command in order to 
  inform server and other users.

* make_packet - Parses user input into packet to send to server. Return None 
  if error (i.e. due to invalid user input).

* private_send, server_send - Helper methods for sending packet to user, server
  respectively.

* HeartbeatThread - sends heartbeat to server every HEARTBEAT_TIME seconds.

* IncomingHandlerThread -sets up client's listening post and handles responses 
  from Server or private messager. When packet recieved, interpret server's
  message and perform action or just print out message.

* Client maintains database of private addresses that it has received from 
  the server. Addresses are only provided by the server after the inquired user
  provides consent. If user already has another user's private address, they
  can private message that user even after being blocked. Blocking user must
  log in with different IP to avoid being contacted.

* When server shuts down and sends notification message, client main thread
  is interrupted and the user can no longer use the chat system. The user
  should press Enter or CTRL-C when prompted to quit the program.

packet.py
--------------
* Packet object used to communicate between chat room server and clients.

* Packet content is stored as dictionary with key=tag, value=tag_value.

* String representation of packet (so that packet can be sent and recieved
  via socket read/write):
    not_msg sender_host,sender_port sender tag:value tag:value ... 
    is_msg sender_host,sender_port sender type target_user msg_content
    ------
    not_msg and is_msg are message flags. Messages may have spaces so the 
    string must be parsed differently. 
    type = public, private, broadcast, system.

