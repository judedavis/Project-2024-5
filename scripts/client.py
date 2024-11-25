from scripts.shared import *
import socket as s
import threading as t

class Client (SockObj):
    def __init__(self, addr, port, data):
        super().__init__("0.0.0.0", self.port, True) # init SockObj
        # No need to bind for client
        self.addr = addr
        self.message = create_message(data)


    def send_message(self):
        """
        Sends Message to target peer
        message = bytes to be sent - bytearray
        target_addr = Target ipv4 of peer - String
        targ_port = Target port of peer - int
        """
        message_len = len(self.message)
        t_print("Attempting connection to: "+self.addr+", "+self.port)
        self.sock.connect((self.addr, self.port))
        total_sent = 0
        while total_sent < message_len:
            sent = self.sock.send(self.message[total_sent:])
            if (sent == 0):
                t_print("No data sent -- Client socket broken, exiting")
                return
            total_sent += sent
        t_print("Message sent to: "+self.addr+", "+self.port)