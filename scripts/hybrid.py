"""
TODO:
- Finish the rest of the protocol operations
- Set up reuse of client socket until you disconnect from the network
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
from time import time, sleep

class TCPHybrid (Server):
    def __init__(self, port=38888) -> None:
        super().__init__(port)
        self.clients = {}
        self.listen_events = {}
        self.timeout = 500
        self.peer_table = PeerTable() # Init the DB
        self.crypt = Crpyt(self.peer_table) # init the local keys
        self.encrypted_prefix = bytes.fromhex('1c1c')
        self.unencrypted_prefix = bytes.fromhex('0000')

    # OVERRIDDEN
    def _handle_connection(self, sock : s.socket, addr : list) -> None:
        # retrieve addr and port
        addr = addr[0]
        port = addr[1]
        # recieve the message
        msg_len, msg_type, session_id, data = self._receive_message(sock) # receieve both encrypted and unencrypted messages
        offset = 0
        # ensure we have a client object with the correct port to respond on
        self._create_client(addr, port, sock)
        if data:
            t_print("received message of type: "+str(msg_type))
        else:
            t_print("received message of type: "+str(msg_type)+" with data: "+str(data))

        # CASE FOR EVERY TYPE OF MESSAGE IN PROTOCOL
        # I would like to use a switch statement, but developing with python 3.9
        if msg_type == MessageTypes.NO_OP:
            """
            We can close the connection
            """
            self._close_client(addr)
            return False

        if msg_type == MessageTypes.HANDSHAKE_REQ:
            """
            expected message = ident|encrypted_sym_len|public_key(sym_key)|signature_len|signature(ident|encrypted_sym_len|public_key(sym_key))
            """
            # get identifier
            peer_ident = data[offset:offset+16] # first 16 bytes is peer identifier
            peer_ident = bytes(peer_ident).hex()
            offset += 16
            # get length of encrypted_sym
            encrypted_sym_len = data[offset:offset+4] # 4 byte length
            encrypted_sym_len = int.from_bytes(encrypted_sym_len, 'little')
            offset += 4
            # get encrypted_sym
            encrypted_sym = data[offset:offset+encrypted_sym_len]
            encrypted_sym = bytes(encrypted_sym)
            offset += encrypted_sym_len
            # reconstruct originally signed message
            signed_message = data[0:offset]
            signed_message = bytes(signed_message)
            # get signature_len
            signature_len = data[offset:offset+4] # 4 byte length
            signature_len = int.from_bytes(signature_len, 'little')
            offset += 4
            # get signature
            signature = data[offset:offset+signature_len]
            signature = bytes(signature)
            offset+=signature_len
            # retrieve peer public key and verify signature
            peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
            peer_pubkey = self.crypt.public_str_to_key(peer_pubkey) # retrieve the peer's public key for verification of the signature
            self.crypt.rsa_verify_signature(signature, signed_message, peer_pubkey)
            sym_key = self.crypt.rsa_decrypt(encrypted_sym).hex()
            # can't do anything with this here so pass it to callback
            self.receieve_handshake(addr, session_id, sym_key, peer_ident)

        if msg_type == MessageTypes.HANDSHAKE_ACK:
            """
            expected message = rand|signatute(rand)
            """
            # get random bits
            rand = data[offset:offset+8] # the random 8 bytes
            rand = bytes(rand)
            offset += 8
            # get signature
            signature = data[offset:] # the rest is the signature
            signature = bytes(signature)
            # get peer public key
            peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
            peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
            peer_pubkey = self.crypt.public_str_to_key(peer_pubkey)

            self.crypt.rsa_verify_signature(signature, rand, peer_pubkey)
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_ACK_2:
            """
            expected message = rand|signatute(rand)
            """
            # get random bits
            rand = data[offset:offset+8] # the random 8 bytes
            rand = bytes(rand)
            offset += 8
            # get signature
            signature = data[offset:] # the rest is the signature
            signature = bytes(signature)
            # get peer public key
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
            
            self.receive_update_peers(addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_ACK_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_FINAL_1:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.UPDATE_PEERS_FINAL_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.EXCHANGE_REQ:
            """
            expected message = ident|public_key_len|public_key|signature_len|signature(ident|public_key_len|public_key)
            """
            if data:

                # get ident
                ident = data[offset:offset+16]
                ident = bytes(ident).hex()
                offset += 16
                # get public key length
                public_key_len = data[offset:offset+4]
                public_key_len = int.from_bytes(public_key_len, 'little')
                offset += 4
                # get public key
                public_key = data[offset:offset+public_key_len]
                public_key = bytes(public_key)
                offset += public_key_len
                # get signed message
                signed_message = data[0:offset]
                signed_message = bytes(signed_message)
                # get signature length
                signature_len = data[offset:offset+4]
                signature_len = int.from_bytes(signature_len, 'little')
                offset += 4
                # get signature
                signature = data[offset:offset+signature_len]
                signature = bytes(signature)
                offset += signature_len

                public_key = self.crypt.public_key_from_bytes(public_key) # deserialise public key
                self.crypt.rsa_verify_signature(signature, signed_message, public_key)
                self.receive_key_exchange(addr, session_id, public_key, ident)
            else: # no attached data
                return # silent treatment
            
        if msg_type == MessageTypes.EXCHANGE_ACK:
            """
            expected message = ident|public_key_len|public_key|signature_len|signature(ident|public_key_len|public_key)
            """
            if data:

                # get ident
                ident = data[offset:offset+16]
                ident = bytes(ident).hex()
                offset += 16
                # get public key length
                public_key_len = data[offset:offset+4]
                public_key_len = int.from_bytes(public_key_len, 'little')
                offset += 4
                # get public key
                public_key = data[offset:offset+public_key_len]
                public_key = bytes(public_key)
                offset += public_key_len
                # get signed message
                signed_message = data[0:offset]
                signed_message = bytes(signed_message)
                # get signature length
                signature_len = data[offset:offset+4]
                signature_len = int.from_bytes(signature_len, 'little')
                offset += 4
                # get signature
                signature = data[offset:offset+signature_len]
                signature = bytes(signature)
                offset += signature_len

                public_key = self.crypt.public_key_from_bytes(public_key) # deserialise public key
                self.crypt.rsa_verify_signature(signature, signed_message, public_key)
                self.set_and_check_event(msg_type, addr, session_id, (ident, public_key), True)
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
            self.receieve_send_data(addr, session_id, data) # pass data as payload
        
        if msg_type == MessageTypes.SEND_DATA_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        return True


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
        msg = b''.join([self.unencrypted_prefix, msg]) # 0000|msg
        t_print(msg)
        return client_obj.send_message(msg)
    
    def _receive_message(self, sock : s.socket):
        """
        Recieve messages both encrypted and unencrypted
        """
        encrypt_flag = recv_n(sock, 2)
        if encrypt_flag == self.encrypted_prefix: # if message is encrypted (starts with 2 delims)
            # expected message = encrypted_prefix|ident|init_vector|auth_tag_len|auth_tag|encrypted_msg_len|encrypted_msg
            # receieve ident
            peer_ident = recv_n(sock, 16)
            peer_ident = peer_ident.hex()
            # receieve init_vector
            init_vector = recv_n(sock, 16)
            init_vector = bytes(init_vector)
            # receieve auth_tag_len
            auth_tag_len = recv_n(sock, 4)
            auth_tag_len = int.from_bytes(auth_tag_len, 'little')
            # receive auth_tag
            auth_tag = recv_n(sock, auth_tag_len)
            auth_tag = bytes(auth_tag)
            # receieve message_len
            encrypted_msg_len = recv_n(sock, 4) # message_len
            encrypted_msg_len = int.from_bytes(encrypted_msg_len, 'little')
            # receieve encrypted_message
            encrypted_msg = recv_n(sock, encrypted_msg_len) # (init_vector|sym_key(msg))
            encrypted_msg = bytes(encrypted_msg)
            # get the our shared key with this peer
            sym_key = self.peer_table.get_user_s_key(peer_ident)
            sym_key = bytes.fromhex(sym_key)
            # decrypt the message
            msg = self.crypt.sym_decrypt(encrypted_msg, sym_key, init_vector, auth_tag)
            # unpack the message
            msg_len, msg_type, session_id, data = split_msg(msg)
            # update the peer table accordingly
            self.peer_table.update_user_last_address(peer_ident, sock.getpeername()[0])
            self.peer_table.update_user_last_time(peer_ident, time())
            return (msg_len, msg_type, session_id, data)
            
        if encrypt_flag == self.unencrypted_prefix: # if message is not encrypted (2 null bytes followed by delim)
            msg_len, msg_type, session_id, data = recv_msg(sock) # receieve the unencrypted message
            return (msg_len, msg_type, session_id, data)
    
        raise Exception # message header wasn't formatted correctly or connection closed TODO


    def _send_encrypted_message(self, addr : str, port: int, msg_type : int, session_id : bytes, sym_key : bytes, payload : bytearray = None) -> bool:
        try:
            client_obj = self.clients[addr]
        except KeyError:
            t_print('Error - No client object exists for the intended address '+addr)
            raise KeyError
            return False
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if not payload:
            payload = bytearray()
        msg = create_message(payload, msg_type, session_id)
        encrypted_msg, init_vector, auth_tag = self.crypt.sym_encrypt(msg, sym_key) # 4 byte unsigned length allows for a very large encrypted message size (much larger than we'll ever need)
        encrypted_msg_len = len(encrypted_msg).to_bytes(4, 'little')
        auth_tag_len = len(auth_tag).to_bytes(4,'little')
        ident = self.peer_table.get_host_identifier() # get ident
        ident = bytes.fromhex(ident) # convert to bytes
        # package message
        packet = b''.join([self.encrypted_prefix, ident, init_vector, auth_tag_len, auth_tag, encrypted_msg_len, encrypted_msg]) # encrypted_prefix|ident|init_vector|auth_tag_len|auth_tag|encrypted_msg_len|encrypted_msg
        t_print(packet)
        return client_obj.send_message(packet)

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
        message = bytearray() # ident|encrypted_sym_len|public_key(sym_key)|signature_len|signature(ident|encrypted_sym_len|public_key(sym_key))
        # get the host ident
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident))
        # generate symmetric key
        sym_key = self.crypt.generate_sym_key()
        # get peer's public key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        peer_pubkey = self.peer_table.get_user_p_key(peer_ident)
        peer_pubkey = self.crypt.public_str_to_key(peer_pubkey)
        # encrypt the symmetric key with their public key
        encrypted_sym_key = self.crypt.rsa_encrypt(sym_key, peer_pubkey)
        encrypted_sym_key_len = len(encrypted_sym_key).to_bytes(4,'little')
        message.extend(encrypted_sym_key_len)
        message.extend(encrypted_sym_key)
        # sign the message thus far
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key)
        signature_len = len(signature).to_bytes(4,'little')
        message.extend(signature_len)
        message.extend(signature)
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

    def receieve_handshake(self, addr : str, session_id : bytes, sym_key : str, peer_ident : str) -> bool:
        # update peer table accordingly
        self.peer_table.update_user_s_key(peer_ident, sym_key)
        sym_key = bytes.fromhex(sym_key)
        # message = rand|signatute(rand)
        message = bytearray()
        # generate random bytes to sign
        rand = r.randbytes(8)
        message.extend(rand)
        # sign random bits
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

        message = bytearray()
        # get peertable payload
        payload = self.peer_table.get_serialised_peers()
        message.extend(payload)
        # get symmetric key from peer table
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        # send encrypted data
        payload = self._send_encrypted_and_wait(addr,
                                      self.port,
                                      MessageTypes.UPDATE_PEERS_REQ,
                                      MessageTypes.UPDATE_PEERS_ACK,
                                      session_id,
                                      sym_key,
                                      message)
        
        # update the peer table with serialised rows
        self.peer_table.update_serialised_peers(payload)

        self._send_encrypted_and_wait(addr,
                            self.port,
                            MessageTypes.UPDATE_PEERS_ACK_2,
                            MessageTypes.UPDATE_PEERS_FINAL_1,
                            session_id,
                            sym_key)
        
        t_print("Update Peer Table finished!")
        return True
    
    def receive_update_peers(self, addr : str, session_id : bytes, payload : bytes) -> bool:
        # update the peer table with serialised rows
        self.peer_table.update_serialised_peers(payload)

        message = bytearray()
        # get peertable payload
        payload = self.peer_table.get_serialised_peers()
        message.extend(payload)
        # get symmetric key from peer table
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        # send encrypted data
        self._send_encrypted_and_wait(addr,
                                      self.port,
                                      MessageTypes.UPDATE_PEERS_ACK,
                                      MessageTypes.UPDATE_PEERS_ACK_2,
                                      session_id,
                                      sym_key,
                                      message)

        self._send_encrypted_message(addr, self.port, MessageTypes.UPDATE_PEERS_FINAL_1, session_id, sym_key)
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
        # message = ident|public_key_len|public_key|signature_len|signature(ident|public_key_len|public_key)
        message = bytearray() 
        # add ident
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident)) # ident
        # add public_key_len
        public_key = self.crypt.public_key_to_bytes(self.crypt.public_key)
        public_key_len = len(public_key).to_bytes(4, 'little')
        message.extend(public_key_len)
        # add public key
        message.extend(public_key)
        # add signature length
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far
        signature_len = len(signature).to_bytes(4, 'little')
        message.extend(signature_len)
        # add signature
        message.extend(signature)

        peer_ident, peer_public_key = self._send_and_wait(addr,
                            self.port,
                            MessageTypes.EXCHANGE_REQ, # send req
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
        # message = ident|public_key_len|public_key|signature_len|signature(ident|public_key_len|public_key)
        message = bytearray() 
        # add ident
        ident = self.peer_table.get_host_identifier()
        message.extend(bytes.fromhex(ident)) # ident
        # add public_key_len
        public_key = self.crypt.public_key_to_bytes(self.crypt.public_key)
        public_key_len = len(public_key).to_bytes(4, 'little')
        message.extend(public_key_len)
        # add public key
        message.extend(public_key)
        # add signature length
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far
        signature_len = len(signature).to_bytes(4, 'little')
        message.extend(signature_len)
        # add signature
        message.extend(signature)

        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.EXCHANGE_ACK, # send req
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
        self._send_and_wait(addr,
                            self.port,
                            MessageTypes.JOIN_NETWORK_REQ,
                            MessageTypes.JOIN_NETWORK_ACK,
                            session_id)
        self.request_key_exchange(addr, session_id)
        self.request_handshake(addr, session_id)
        self.request_update_peers(addr, session_id)
        t_print("Join network finished!")
        return True
    
    def receive_join_network(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.JOIN_NETWORK_ACK, session_id)
        self._client_response(addr) # wait for key exchange
        self._client_response(addr) # wait for handshake
        self._client_response(addr) # wait for update peers
        t_print("Join network finished!")
        return True
    
    def request_keep_alive(self, addr : str, session_id : bytes = None) -> bool:
        """
        Send an empty encrypted message to the peer and wait for encrypted ack.
        Encrypted messages automatically update the peer's db entry
        """
        if (not session_id):
            session_id = self._generate_session_id()
        # retrieve the peer's sym_key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        # send keep alive and wait for ack
        self._send_encrypted_and_wait(addr,
                                      self.port,
                                      MessageTypes.KEEP_ALIVE_REQ,
                                      MessageTypes.KEEP_ALIVE_ACK_1,
                                      session_id,
                                      sym_key)
        t_print("Keep Alive finished!")
        return True
    
    def receive_keep_alive(self, addr : str, session_id : bytes) -> bool:
        """
        Receive encrypted empty message and send ack.
        Encrypted messages automatically update the peer's db entry
        """
        # retrieve the peer's sym_key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        # send ack
        self._send_encrypted_message(addr, self.port, MessageTypes.KEEP_ALIVE_ACK_1, session_id, sym_key)
        t_print("Keep Alive finished!")
        return True
    
    def request_send_data(self, addr : str, payload : bytes, session_id : bytes = None) -> bool:
        """
        Send an encrypted payload to the peer and wait for ack
        """
        if (not session_id):
            session_id = self._generate_session_id()
        # retrieve the peer's sym_key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        self._send_encrypted_and_wait(addr,
                                      self.port,
                                      MessageTypes.SEND_DATA_REQ,
                                      MessageTypes.SEND_DATA_ACK,
                                      session_id,
                                      sym_key,
                                      payload)
        t_print("Send data finished!")
        return True
    
    def receieve_send_data(self, addr : str, session_id : bytes, payload : bytes) -> bytes:
        """
        Recieve encrypted payload from peer and send ack
        """
        # retrieve the peer's sym_key
        peer_ident = self.peer_table.get_identifier_by_last_addr(addr)
        sym_key = self.peer_table.get_user_s_key(peer_ident)
        sym_key = bytes.fromhex(sym_key)
        self._send_encrypted_message(addr, self.port, MessageTypes.SEND_DATA_ACK, session_id, sym_key)
        t_print("Send data finished!")
        return payload
    
    def send_no_op(self, addr: str, session_id : bytes = None) -> bool:
        """
        close the application level connection with the target
        """
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.NO_OP, session_id)
        self._close_client(addr)
        t_print("No-op sent!")
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
        