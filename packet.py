"""
Packet object used to communicate between chat room server and clients.

Packet content is stored as dictionary with key=tag, value=tag_value.
String representation of packet:
    not_msg sender_host,sender_port sender tag:value tag:value ... 
    is_msg sender_host,sender_port sender type target_user msg_content
    ------
    not_msg and is_msg are message flags. Messages may have spaces so the string
    must be parsed differently. type = public, private, broadcast, system.

Author: Hyonjee Joo
"""

from collections import defaultdict

class Packet(object):
    def __init__(self, sender_host=None, sender_port=None, sender=None):
        self.sender_host = sender_host
        self.sender_port = str(sender_port)
        self.sender = sender
        self.content = defaultdict(lambda: "")
        self.is_msg = False
    
    def parse(self, string):
        fields = string.strip().split(" ")
        self.sender_host, self.sender_port = fields[1].split(",") 
        self.sender = fields[2]
        if fields[0] == "is_msg":
            self.is_msg = True
            self.content["type"] = fields[3]
            self.content["to"] = fields[4]
            self.content["message"] = " ".join(fields[5:])
        if fields[0] == "not_msg":
            for field in fields[3:]:
                tag, value = field.strip().split(":")
                self.content[tag] = value

    def to_string(self):
        if self.is_msg:
            result_string = "is_msg "
            result_string += self.sender_host + "," + self.sender_port + " "
            result_string += self.sender + " "
            result_string += self.content["type"] + " "
            if self.content["to"]:
                result_string += self.content["to"] + " "
            result_string += self.content["message"]
        else:
            result_string = "not_msg "
            result_string += self.sender_host + "," + self.sender_port
            result_string += " " + self.sender
            for tag in self.content:
                result_string += " " + tag + ":" + self.content[tag]
        return result_string

    def create_msg(self, msg_type, message, to=None):
        self.is_msg = True
        self.content["type"] = msg_type
        if to is not None:
            self.content["to"] = to
        self.content["message"] = message

    def add_fields(self, tag_value_tuple_list):
        for tag, value in tag_value_tuple_list:
            self.content[tag] = value

    def get_field(self, tag):
        return self.content[tag]

    def get_sender_addr(self):
        return (self.sender_host, int(self.sender_port))
