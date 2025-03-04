import socket as s
import threading as t
from enum import Enum

class SockObj ():
    """
    Parent Class for Client and Server objects:
    addr = ipv4 - String
    port = desired TCP Port - Int
    so_reuse = Optional socket reuse flag (for debugging) - Boolean
    """
    def __init__(self, addr : str, port : int, so_reuse : bool) -> None:
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        if so_reuse:
            self.sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1) # So address can be immediately reused without waiting for the dead socket to expire
        self.addr = addr
        self.port = port

    def bind(self) -> None:
         self.sock.bind((self.addr, self.port))
        
class MessageTypes ():
    HANDSHAKE = 1

def create_header(payload: bytearray, msg_type: int) -> bytearray:
    """
    Generates a header for an intended payload
    payload = Intended Payload - bytearray
    msg_type = 1 byte bitfield - integer
    """
    header = bytearray()
    header_len = len(payload)
    header_len = header_len.to_bytes(4, 'little')
    header.extend(header_len)
    msg_type = msg_type.to_bytes(1, 'little')
    header.extend(msg_type)
    return header

def create_message(data: bytearray, msg_type: int) -> bytearray:
    """
    Generates a message that is ready to be sent from the given payload
    data = Intended Payload - bytearray
    msg_type = = 1 byte bitfield - bytearray
    """
    message = bytearray()
    header = create_header(data, msg_type)
    message.extend(header)
    message.extend(data)
    t_print(message)
    return message

def recv_n (sock : s.socket, n : int) -> bytearray:
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

def recv_msg (sock : s.socket) -> bytearray:
    """
    Recieves variable length message on given socket
    """
    msg_len = sock.recv(4) # Get message length header
    msg_len = int.from_bytes(msg_len, 'little')
    msg_type = sock.recv(1) # Get message type
    msg_type = int.from_bytes(msg_type, 'little')
    payload = recv_n(sock, msg_len) # Get rest of message
    return (msg_type, msg_len, payload)

def t_print(string : str) -> None:
        """
        Prints string with thread name prefixed
        """
        if t.current_thread() != t.main_thread():  
            print(t.current_thread().name+": "+str(string))
            return
        print(string)