"""
TODO:
-
- Salvage the code portion of the report, turning it into a implementation header
- Do more literature review (read some papers dawg)
"""

import threading as t
import scripts.client as client
from scripts.server import Server
from scripts.crypt import Crpyt
from scripts.shared import *
import random as r
from db.peer_table import PeerTable
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from time import time

class TCPHybrid (Server):
    def __init__(self, port=38888) -> None:
        super().__init__(port)
        self.clients = {}
        self.listen_events = {}
        self.timeout = 500
        self.peer_table = PeerTable() # Init the DB
        self.crypt = Crpyt(self.peer_table) # init the local keys
        self.delimiter = bytes.fromhex('1c1c')

    # OVERRIDDEN
    def _handle_connection(self, sock : s.socket, addr : list) -> None:
        addr = addr[0]
        port = addr[1]
        msg_len, msg_type, session_id, data = self._receive_message(sock) # receieve both encrypted and unencrypted messages
        if data:
            t_print("received message of type: "+str(msg_type))
        else:
            t_print("received message of type: "+str(msg_type)+" with data: "+str(data))

        # CASE FOR EVERY TYPE OF MESSAGE IN PROTOCOL
        # I would like to use a switch statement, but developing with python 3.9
        
        if msg_type == MessageTypes.HANDSHAKE_REQ:
            self._create_client(addr, port, sock) # init a new client with the active socket
            t_print(data)
            # expected message = ident|public_key(sym_key)|signature(ident|public_key(sym_key))
            peer_ident, tmp, data = data.partition(self.delimiter) # the peer's identifier
            peer_ident = bytes(peer_ident)
            encrypted_sym_key, tmp, data = data.partition(self.delimiter) # symmetric key encrypted with our public key
            encrypted_sym_key = bytes(encrypted_sym_key) 
            signature, tmp, data = data.partition(self.delimiter)
            signature = bytes(signature) # signature generated with the peer's private key
            signed_message = b''.join([peer_ident, self.delimiter, encrypted_sym_key, self.delimiter]) # ident|public_key(sym_key)|
            peer_pubkey = self.peer_table.get_user_p_key(peer_ident.hex())
            peer_pubkey = self.crypt.public_str_to_key(peer_pubkey) # retrieve the peer's public key for verification of the signature
            self.crypt.rsa_verify_signature(signature, signed_message, peer_pubkey)
            sym_key = self.crypt.rsa_decrypt(encrypted_sym_key)
            # can't do anything with this here so pass it to callback
            self.receieve_handshake(addr, session_id, sym_key, peer_ident)

        if msg_type == MessageTypes.HANDSHAKE_ACK:
            # rand|signatute(rand)
            rand = data[0:8] # the random 8 bytes
            rand = bytes(rand)
            signature = data[8:] # the rest is the signature
            signature = bytes(signature)
            peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
            peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
            peer_pubkey = self.crypt.public_str_to_key(peer_pubkey)
            self.crypt.rsa_verify_signature(signature, rand, peer_pubkey)
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_ACK_2:
            # rand|signatute(rand)
            rand = data[0:8] # the random 8 bytes
            rand = bytes(rand)
            signature = data[8:] # the rest is the signature
            signature = bytes(signature)
            peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
            peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
            peer_pubkey = self.crypt.public_str_to_key(peer_pubkey)
            self.crypt.rsa_verify_signature(signature, rand, peer_pubkey)
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_FINAL_1:
            """
            Unused
            """
            pass

        if msg_type == MessageTypes.HANDSHAKE_FINAL_2:
            """
            Unused
            """
            pass
        
        if msg_type == MessageTypes.UPDATE_PEERS_REQ:
            self.receive_update_peers(addr, session_id)

        if msg_type == MessageTypes.UPDATE_PEERS_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_ACK_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_FINAL_1:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_FINAL_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.EXCHANGE_REQ:
            if data: # expected message = ident|public_key|signature(ident|public_key)
                self._create_client(addr, port, sock) # init a new client with the active socket
                ident, tmp, data = data.partition(self.delimiter) # identifier
                ident = bytes(ident)
                public_key_bytes, tmp, data = data.partition(self.delimiter) # peer_public_key
                public_key_bytes = bytes(public_key_bytes) 
                signature, tmp, data = data.partition(self.delimiter)
                signature = bytes(signature) # signature(ident|peer_public_key)
                signed_message = b''.join([ident, self.delimiter, public_key_bytes]) # ident|peer_public_key
                public_key = self.crypt.public_key_from_bytes(public_key_bytes)
                self.crypt.rsa_verify_signature(signature, signed_message, public_key)
                self.receive_key_exchange(addr, session_id, public_key, ident.hex())
            else: # no attached data
                return # silent treatment
            
        if msg_type == MessageTypes.EXCHANGE_ACK:
            if data: # ident|peer_public_key|signature(ident|temp_public_key)
                ident, tmp, data = data.partition(self.delimiter) # identifier
                ident = bytes(ident)
                public_key_bytes, tmp, data = data.partition(self.delimiter) # peer_public_key
                public_key_bytes = bytes(public_key_bytes) 
                signature, tmp, data = data.partition(self.delimiter)
                signature = bytes(signature) # signature(ident|peer_public_key)
                signed_message = b''.join([ident, self.delimiter, public_key_bytes])
                public_key = self.crypt.public_key_from_bytes(public_key_bytes)
                self.crypt.rsa_verify_signature(signature, signed_message, public_key)
                self.set_and_check_event(msg_type, addr, session_id, (ident.hex(), public_key), True)
            else: # no attached data
                self.set_and_check_event(msg_type, addr, session_id, None, False)
            

        if msg_type == MessageTypes.EXCHANGE_ACK_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.EXCHANGE_FINAL:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.JOIN_NETWORK_REQ:
            self.receive_join_network(addr, session_id)
        
        if msg_type == MessageTypes.JOIN_NETWORK_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.KEEP_ALIVE_REQ:
            self.receive_keep_alive(addr, session_id)
        
        if msg_type == MessageTypes.KEEP_ALIVE_ACK_1:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.SEND_DATA_REQ:
            self.receieve_send_data(addr, session_id)
        
        if msg_type == MessageTypes.SEND_DATA_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        return


    def _create_client(self, addr : str, port : int, sock : s.socket = None) -> client.Client:
        """
        Generates a new client object, adds it to the client list
        Returns the created client object
        """
        if self.clients.__contains__(addr) and not sock: # if client already exists, and no socket was supplied
            client_obj = self.clients[addr]
            return client_obj
        client_obj = client.Client(addr, port, sock)
        self.clients[addr] = client_obj
        return client_obj
    
    def _client_response(self, addr):
        """
        Retrieves corrosponding client object and calls handle connection on it
        Allowing the client object to recieve data on it's connection
        """
        if self.clients.__contains__(addr):
            client_obj = self.clients[addr]
            self._handle_connection(client_obj.sock, [client_obj.addr, client_obj.port])
    
    def _close_client(self, addr : str) -> bool:
        """
        Shuts down a client object and removes it from client list
        Returns True if successful, False if no client object exists for the given address
        """
        if self.clients.__contains__(addr):
            self.clients[addr].exit() # shut down the connection if applicable
            self.clients.pop(addr) # remove socket from clients
            return True
        return False
    
    # Event funcs

    def _create_event(self, msg_type : int, addr : str, session_id : bytes) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            return self._get_event(msg_type, addr, session_id) # if event already exists, just return that
        if (msg_type, addr, session_id) not in self.listen_events:
            data = None
            success = None
            self.listen_events[(msg_type, addr, session_id)] = [t.Event(), data, success] # create a new event for this specific connection
            return self._get_event(msg_type, addr, session_id)
        return False

    def _get_event(self, msg_type : int, addr : str, session_id : bytes) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            return self.listen_events[(msg_type, addr, session_id)][0] # get and return the event
        return False
    
    def _get_data(self, msg_type : int, addr : str, session_id : bytes) -> bytearray:
        if (msg_type, addr, session_id) in self.listen_events:
            return self.listen_events[(msg_type, addr, session_id)][1] # get and return the data
        return None

    def _set_data(self, msg_type : int, addr : str, session_id : bytes, data : any) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events[(msg_type, addr, session_id)][1] = data # set the data field
            return True
        return False
    
    def _get_success(self, msg_type : int, addr : str, session_id : bytes) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            return self.listen_events[(msg_type, addr, session_id)][2]
        return None
    
    def _set_success(self, msg_type : int, addr : str, session_id : bytes, success : bool) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events[(msg_type, addr, session_id)][2] = success
            return True
        return False
    
    def _remove_event(self, msg_type : int, addr : str, session_id : bytes) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events.pop((msg_type, addr, session_id))
            return True
        return False

    def _check_event(self, msg_type : int, addr : str, session_id : bytes) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events[(msg_type, addr, session_id)][0].set() # set this event if it exists
            return self._get_event(msg_type, addr, session_id)
        return False
    
    def set_and_check_event(self, msg_type : int, addr : str, session_id : bytes, data: any, success : bool = None) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self._set_data(msg_type, addr, session_id, data)
            self._set_success(msg_type, addr, session_id, success)
            self.listen_events[(msg_type, addr, session_id)][0].set() # set this event if it exists
            t_print("event set and checked successfully")
            return True
        t_print("event not set and checked successfully")
        return False
    
    def async_wait_event(self, msg_type : int, addr : str, session_id : bytes) -> any:
        """
        Observe an event without deleting
        """
        event = self._get_event(msg_type, addr, session_id)
        if not event: # if event does not exist then create it
            event = self._create_event(msg_type, addr, session_id)
        if event:
            t_print("Asynchronously waiting for event of type: "+str(msg_type))
            if event.wait(self.timeout):
                if self._get_success(msg_type, addr, session_id) == False:
                    t_print("Event of type: "+str(msg_type)+" was unsuccessful")
                    return None
                t_print("Asynchronous Event successful: "+str(msg_type))
                data = self._get_data(msg_type, addr, session_id)
                return data # return without deleting event, since we only want to observe
            t_print("Asynchronous Event timed out of type: "+str(msg_type))
        t_print("Asynchronous Event failed of type: "+str(msg_type))
        return None # event was not found
    
    def wait_event(self, msg_type : int, addr : str, session_id : bytes) -> any:
        event = self._create_event(msg_type, addr, session_id)
        t_print("Creating event of type: "+str(msg_type))
        if event:
            t_print("Waiting for event of type: "+str(msg_type))
            if event.wait(self.timeout):
                if self._get_success(msg_type, addr, session_id) == False:
                    t_print("Event of type: "+str(msg_type)+" was unsuccessful")
                    self._remove_event(msg_type, addr, session_id)
                    return None
                t_print("Event of type: "+str(msg_type)+" successful")
                data = self._get_data(msg_type, addr, session_id)
                self._remove_event(msg_type, addr, session_id)
                return data
            t_print("Event timed out of type: "+str(msg_type))
            self._remove_event(msg_type, addr, session_id)
            return None
        else:
            t_print("Event failed of type: "+str(msg_type))
            return None # None if timeout, or event failed to be created

    def _send_message(self, addr : str, port : int, msg_type : int, session_id : bytes, payload : bytearray = None) -> bool:
        """
        Sends data
        """
        try:
            client_obj = self.clients[addr]
        except KeyError:
            t_print('Error - No client object exists for the intended address '+addr)
            return False
        if isinstance(payload, str): # accept string payloads, but convert them to bytes
            payload = payload.encode('utf-8')
        if not payload: # if no payload is given, create empty bytearray obj
            payload = bytearray()
        msg = create_message(payload, msg_type, session_id)
        # unencrypted messages are preceeded by an empty byte
        msg = b''.join([bytes(2), self.delimiter, msg]) # 0000|msg
        t_print(msg)
        return client_obj.send_message(msg)
    
    def _receive_message(self, sock : s.socket):
        """
        Recieve messages both encrypted and unencrypted
        """
        encrypt_flag = recv_n(sock, 4)
        if encrypt_flag == bytes.fromhex('1c1c1c1c'): # if message is encrypted (starts with 2 delims)
            # expected message = ident.message_len.init_vector|auth_tag|sym_key(msg)
            # receieve ident
            peer_ident = recv_n(sock, 16)
            peer_ident = peer_ident.hex()
            # receieve message_len
            encrypted_msg_len = recv_n(sock, 4) # message_len
            encrypted_msg_len = int.from_bytes(encrypted_msg_len, 'little')
            # receieve init_vector auth_tag and encrypted message
            encrypted_msg = recv_n(sock, encrypted_msg_len) # (init_vector|sym_key(msg))
            init_vector, tmp, encrypted_msg = encrypted_msg.partition(self.delimiter) # init_vector, auth_tag|sym_key(msg)
            init_vector = bytes(init_vector)
            auth_tag, tmp, encrypted_msg = encrypted_msg.partition(self.delimiter) # auth_tag, sym_key(msg)
            auth_tag = bytes(auth_tag)
            encrypted_msg = bytes(encrypted_msg)
            # get the our shared key with this peer
            sym_key = self.peer_table.get_user_s_key(peer_ident)
            sym_key = bytes.fromhex(sym_key)
            # decrypt the message
            msg = self.crypt.sym_decrypt(encrypted_msg, sym_key, init_vector, auth_tag)
            # unpack the message
            msg_len, msg_type, session_id, data = split_msg(msg)
            return (msg_len, msg_type, session_id, data)
            
        if encrypt_flag == bytes.fromhex('00001c1c'): # if message is not encrypted (2 null bytes followed by delim)
            msg_len, msg_type, session_id, data = recv_msg(sock) # receieve the unencrypted message
            return (msg_len, msg_type, session_id, data)
    
        raise Exception # message header wasn't formatted correctly or connection closed TODO


    def _send_encrypted_message(self, addr : str, port: int, msg_type : int, session_id : bytes, sym_key : bytes, payload : bytearray = None) -> bool:
        try:
            client_obj = self.clients[addr]
        except KeyError:
            t_print('Error - No client object exists for the intended address '+addr)
            return False
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if not payload:
            payload = bytearray()
        msg = create_message(payload, msg_type, session_id)
        encrypted_msg, init_vector, auth_tag = self.crypt.sym_encrypt(msg, sym_key) # 4 byte unsigned length allows for a very large encrypted message size (much larger than we'll ever need)
        encrypted_msg = b''.join([init_vector, self.delimiter, auth_tag, self.delimiter, encrypted_msg])
        encrypted_msg_len = len(encrypted_msg).to_bytes(4, 'little')
        ident = self.peer_table.get_host_identifier() # get ident
        ident = bytes.fromhex(ident) # convert to bytes
        # two delimiters preceeds any data to tell the receiever this message is encrypted
        encrypted_msg = b''.join([self.delimiter, self.delimiter, ident, encrypted_msg_len, encrypted_msg]) # ||ident.message_len.init_vector|auth_tag|sym_key(msg)
        t_print(encrypted_msg)
        return client_obj.send_message(encrypted_msg)

    def _generate_session_id(self) -> bytes:
        return r.randbytes(8)
            
    def _send_encrypted_and_wait(self, addr : str, port : int, send_type : int, wait_type : int, session_id : bytes, sym_key : bytes, message : bytes = None) -> any:
        self._create_event(wait_type, addr, session_id)
        self._send_encrypted_message(addr, port, send_type, session_id, sym_key, message)
        self._client_response(addr)
        data = self.wait_event(wait_type, addr, session_id)
        return data

    def _send_and_wait(self, addr : str, port : int, send_type : int, wait_type : int, session_id : bytes, message : bytes = None) -> any:
        self._create_event(wait_type, addr, session_id)
        self._send_message(addr, port, send_type, session_id, message)
        self._client_response(addr)
        data = self.wait_event(wait_type, addr, session_id)
        return data

    ## Protocol Operations

    def request_handshake(self, addr : str, session_id : bytes = None) -> bool:
        # here we get our public key ready
        if (not session_id): # if session id not provided for this interaction, generate a new one
            session_id = self._generate_session_id()
        message = bytearray() # ident|public_key(sym_key)|signature(ident|public_key(sym_key))
        # get the host ident
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident))
        message.extend(self.delimiter)
        # generate symmetric key
        sym_key = self.crypt.generate_sym_key()
        # encrypt the key with the peer's public key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
        peer_pubkey = self.crypt.public_str_to_key(peer_pubkey)
        message.extend(self.crypt.rsa_encrypt(sym_key, peer_pubkey))
        message.extend(self.delimiter)
        # sign the message thus far
        message.extend(self.crypt.rsa_generate_signature(message, self.crypt.private_key))
        # save symmetric key to peer_table (is this too early?)
        self.peer_table.update_user_s_key(peer_ident, sym_key.hex())

        # send HANDSHAKE_REQ and wait for HANDSHAKE_ACK
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.HANDSHAKE_REQ, # send
                            MessageTypes.HANDSHAKE_ACK, # receieve
                            session_id,
                            message)
        
        # message = rand|signatute(rand)
        message = bytearray()
        rand = r.randbytes(8) # 8 bytes of random data to sign
        message.extend(rand)
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key)
        message.extend(signature)

        # send HANDSHAKE_FINAL_2
        self._send_encrypted_message(addr, self.port, MessageTypes.HANDSHAKE_ACK_2, session_id, sym_key, message)
        t_print("Handshake finished!")
        return True

    def receieve_handshake(self, addr : str, session_id : bytes, sym_key : str, peer_ident : bytes) -> bool:
        # message = rand|signatute(rand)
        message = bytearray()
        rand = r.randbytes(8) # 8 bytes of random data to sign
        message.extend(rand)
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key)
        message.extend(signature)

        # send HANDSHAKE_ACK and wait for HANDSHAKE_FINAL_2
        self._send_encrypted_and_wait(addr, 
                                      self.port,
                                      MessageTypes.HANDSHAKE_ACK,
                                      MessageTypes.HANDSHAKE_ACK_2,
                                      session_id,
                                      sym_key,
                                      message)
        

        t_print("Handshake finished!")
        return True
    
    def request_update_peers(self, addr : str, session_id : bytes = None) -> bool:
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.UPDATE_PEERS_REQ,
                            MessageTypes.UPDATE_PEERS_ACK,
                            session_id)
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.UPDATE_PEERS_ACK_2,
                            MessageTypes.UPDATE_PEERS_FINAL_1,
                            session_id)
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_FINAL_2, session_id)
        t_print("Update Peer Table finished!")
        return True
    
    def receive_update_peers(self, addr : str, session_id : bytes) -> bool:
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.UPDATE_PEERS_ACK,
                            MessageTypes.UPDATE_PEERS_ACK_2,
                            session_id)
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.UPDATE_PEERS_FINAL_1,
                            MessageTypes.UPDATE_PEERS_FINAL_2,
                            session_id)
        t_print("Update Peer Table finished!")
        return True
    
    def request_key_exchange(self, addr: str, session_id : bytes = None) -> RSAPublicKey:
        """
        Request a key exchange with a peer
        addr = Address of peer
        session_id = id of the session
        Returns an RSA Public key retrieved from the peer
        """
        if (not session_id):
            session_id = self._generate_session_id()
        message = bytearray() # create (ident|public_key|signature(ident|public_key))
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident)) # ident
        message.extend(self.delimiter) # |
        message.extend(self.crypt.public_key_to_bytes(self.crypt.public_key)) # public_key
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far

        self.crypt.rsa_verify_signature(signature, message, self.crypt.public_key)

        message.extend(self.delimiter) # |
        message.extend(signature) # signature(ident|public_key)
        peer_ident, peer_public_key = self._send_and_wait(addr,
                            self.port,
                            MessageTypes.EXCHANGE_REQ, # ident|public_key|signature(ident|public_key)
                            MessageTypes.EXCHANGE_ACK, # wait for ack
                            session_id,
                            message)
        if not peer_public_key: # if we didn't recieve any data, or if the event failed, exit
            return None
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.EXCHANGE_ACK_2, # send ack
                            MessageTypes.EXCHANGE_FINAL, # wait for final ack
                            session_id) 
        peer_public_key_str = self.crypt.public_key_to_bytes(peer_public_key).decode('utf-8') # convert to suitable format for PeerTable
        self.peer_table.new_user(peer_public_key_str, peer_ident, addr, time()) # add peer to peer table
        t_print("Key exchange finished!")
        return peer_public_key
    
    def receive_key_exchange(self, addr : str, session_id : bytes, peer_public_key : RSAPublicKey, peer_ident : str) -> RSAPublicKey:
        """
        Handles an incoming key exchange
        addr = address of the initiating peer
        session_id = id of the session
        peer_public_key = the RSA Public key sent by the initiator
        Returns the RSA Public key retreived from the initiator
        """
        if not peer_public_key: # if we didn't recieve any data, or if the event failed, exit
            return None
        message = bytearray() # create (ident|public_key|signature(ident|public_key))
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident)) # ident
        message.extend(self.delimiter) # |
        message.extend(self.crypt.public_key_to_bytes(self.crypt.public_key)) # public_key
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far
        
        self.crypt.rsa_verify_signature(signature, message, self.crypt.public_key)

        message.extend(self.delimiter) # |
        message.extend(signature) # signature(ident|public_key)
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.EXCHANGE_ACK, # ident|public_key|signature(ident|public_key)
                            MessageTypes.EXCHANGE_ACK_2, # wait for ack
                            session_id,
                            message)
        self._send_message(addr, self.port, MessageTypes.EXCHANGE_FINAL, session_id) # send final ack
        peer_public_key_str = self.crypt.public_key_to_bytes(peer_public_key).decode('utf-8') # convert to suitable format for PeerTable
        self.peer_table.new_user(peer_public_key_str, peer_ident, addr, time()) # add peer to peer to table
        t_print("Key exchange finished!")
        return peer_public_key

    def request_join_network(self, addr : str, session_id : bytes = None) -> bool:
        # the idea so far
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.JOIN_NETWORK_REQ, session_id)
        self.wait_event(MessageTypes.JOIN_NETWORK_ACK, addr, session_id)
        self.request_key_exchange(addr, session_id)
        self.request_handshake(addr, session_id)
        self.request_update_peers(addr, session_id)
        t_print("Join network finished!")
        return True
    
    def receive_join_network(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.JOIN_NETWORK_ACK, session_id)
        self.async_wait_event(MessageTypes.UPDATE_PEERS_FINAL_2, addr, session_id) # wait until the update peers function is complete
        t_print("Join network finished!")
        return True
    
    def request_keep_alive(self, addr : str, session_id : bytes = None) -> bool:
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.KEEP_ALIVE_REQ, session_id)
        self.wait_event(MessageTypes.KEEP_ALIVE_ACK_1, addr, session_id)
        t_print("Keep Alive finished!")
        return True
    
    def receive_keep_alive(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.KEEP_ALIVE_ACK_1, session_id)
        t_print("Keep Alive finished!")
        return True
    
    def request_send_data(self, addr : str, session_id : bytes = None) -> bool:
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.SEND_DATA_REQ, session_id)
        self.wait_event(MessageTypes.SEND_DATA_ACK, addr, session_id)
        t_print("Send data finished!")
        return True
    
    def receieve_send_data(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.SEND_DATA_ACK, session_id)
        t_print("Send data finished!")
        return True


    def start_server(self) -> None:
        server_thread = t.Thread(target=self.receive_peers,
                                     name="Server Thread")
        self.threads[server_thread.ident] = server_thread
        self.threads[server_thread.ident].start()

    def exit(self) -> None:
        self.sock.shutdown(s.SHUT_RDWR)
        self.sock.close() # stop the server
        for client in self.clients:
            client.exit()
        