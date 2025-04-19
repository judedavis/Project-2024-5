import socket as s
import threading as t

class SockObj ():
    """
    Parent Class for Client and Server objects:
    addr = ipv4 - String
    port = desired TCP Port - Int
    so_reuse = Optional socket reuse flag (for debugging) - Boolean
    socket = can be supplied to use an already created socket
    """
    def __init__(self, addr : str, port : int, so_reuse : bool, socket : s.socket = None) -> None:
        if socket: # if a pre connected socket is supplied
            self.sock = socket
            addr = self.sock.getpeername() # retrieve the remote endpoint address/ port
            self.addr = addr[0]
            self.port = addr[1]
        else: # otherwise we need to create out own
            self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
            self.addr = addr
            self.port = port
        if so_reuse:
            self.sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1) # So address can be immediately reused without waiting for the dead socket to expire

    def bind(self) -> None:
         self.sock.bind((self.addr, self.port))

class MessageTypes ():
    HANDSHAKE_REQ = 1
    HANDSHAKE_ACK = 2
    HANDSHAKE_ACK_2 = 3
    HANDSHAKE_FINAL_1 = 4
    HANDSHAKE_FINAL_2 = 5
    UPDATE_PEERS_REQ = 6
    UPDATE_PEERS_ACK = 7
    UPDATE_PEERS_ACK_2 = 8
    UPDATE_PEERS_FINAL_1 = 9
    UPDATE_PEERS_FINAL_2 = 10
    EXCHANGE_REQ = 11
    EXCHANGE_ACK = 12
    EXCHANGE_ACK_2 = 13
    EXCHANGE_FINAL = 14
    JOIN_NETWORK_REQ = 15
    JOIN_NETWORK_ACK = 16
    KEEP_ALIVE_REQ = 17
    KEEP_ALIVE_ACK_1 = 18
    KEEP_ALIVE_ACK_2 = 19
    SEND_DATA_REQ = 20
    SEND_DATA_ACK = 21

def create_header(payload: bytearray, msg_type: int, session_id: bytes) -> bytearray:
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
    header.extend(session_id)
    return header

def create_message(data: bytearray, msg_type: int, session_id: bytes) -> bytearray:
    """
    Generates a message that is ready to be sent from the given payload
    data = Intended Payload - bytearray
    msg_type = = 1 byte bitfield - bytearray
    """
    message = bytearray()
    header = create_header(data, msg_type, session_id)
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

def recv_msg (sock : s.socket) -> tuple:
    """
    Recieves variable length message on given socket
    """
    msg_len = recv_n(sock, 4) # Get message length header
    msg_len = int.from_bytes(msg_len, 'little')
    msg_type = recv_n(sock, 1) # Get message type
    msg_type = int.from_bytes(msg_type, 'little')
    session_id = recv_n(sock, 8) # Get session ID
    session_id = bytes(session_id)
    if msg_len == 0:
        payload = None
    else:
        payload = recv_n(sock, msg_len) # Get rest of message
    return (msg_len, msg_type, session_id, payload)

def t_print(string : str) -> None:
        """
        Prints string with thread name prefixed
        """
        if t.current_thread() != t.main_thread():  
            print(t.current_thread().name+": "+str(string))
            return
        print(string)