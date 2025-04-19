from scripts.shared import *
import socket as s
import threading as t

class Client (SockObj):
    def __init__(self, addr, port, sock = None) -> None:
        super().__init__(addr, port, True, sock) # init SockObj
        self.sock.connect((self.addr, self.port)) # make sure the connection is live before we start sending data
        # No need to bind for client

    def send_message(self, data) -> bool:
        """
        Sends Message to target peer
        message = bytes to be sent - bytearray
        target_addr = Target ipv4 of peer - String
        targ_port = Target port of peer - int
        """
        if not data:
            # if data is null
            data = bytearray()
        message_len = len(data)
        t_print("Attempting connection to: "+self.addr+", "+str(self.port))
        total_sent = 0
        while total_sent < message_len:
            sent = self.sock.send(data[total_sent:])
            if (sent == 0):
                t_print("No data sent -- Client socket broken, exiting")
                return False
            total_sent += sent
        t_print("Message sent to: "+self.addr+", "+str(self.port))
        return True
    
    def exit(self) -> None:
        # anything else that needs to be done?
        self.sock.shutdown(s.SHUT_RDWR)
        self.sock.close()