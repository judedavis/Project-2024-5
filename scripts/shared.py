import socket as s
import threading as t

class SockObj ():
    """
    Parent Class for Client and Server objects:
    addr = ipv4 - String
    port = desired TCP Port - Int
    so_reuse = Optional socket reuse flag (for debugging) - Boolean
    """
    def __init__(self, addr, port, so_reuse):
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        if so_reuse:
            self.sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1) # So address can be immediately reused without waiting for the dead socket to expire
        self.addr = addr
        self.port = port

    def bind(self):
         self.sock.bind((self.addr, self.port))
        


def create_header(self, payload):
    """
    Generates a header for an intended payload
    payload = Intended Payload - bytearray
    """
    header = bytearray()
    header_len = len(payload)
    header_len = header_len.to_bytes(4, 'little')
    header.extend(header_len)
    return header

def create_message(self, data):
    """
    Generates a message that is ready to be sent from the given payload
    data = Intended Payload - bytearray
    """
    message = bytearray()
    header = self.create_header(data)
    message.extend(header)
    message.extend(data)

def recv_n (sock, n):
    """
    Recieve n bytes on socket
    """
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n-len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def recv_msg (sock):
    """
    Recieves variable length message on given socket
    """
    msg_len = sock.recv(4) # Get message length header
    msg_len = int.from_bytes(msg_len, 'little')
    msg = recv_n(sock, msg_len) # Get rest of message
    return msg

def t_print(string):
        """
        Prints string with thread name prefixed
        """
        if t.current_thread() != t.main_thread():  
            print(t.current_thread().name+": "+str(string))
            return
        print(string)