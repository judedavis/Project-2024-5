import threading as t
import scripts.client as client
from scripts.server import Server
from scripts.crypt import Crpyt
from scripts.shared import *
import random as r # good or bad?
from db.peer_table import PeerTable
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class TCPHybrid (Server):
    def __init__(self, port=38888) -> None:
        super().__init__(port)
        self.clients = []
        self.listen_events = {}
        self.timeout = 500
        self.peer_table = PeerTable() # Init the DB
        self.crypt = Crpyt(self.peer_table) # init the local keys
        self.delimiter = bytes.fromhex('1c')

    # OVERRIDDEN
    def _handle_connection(self, sock : s.socket, addr : list) -> None:
        addr = addr[0]
        msg_len, msg_type, session_id, data = recv_msg(sock)

        if data:
            t_print("received message of type: "+str(msg_type))
        else:
            t_print("received message of type: "+str(msg_type)+" with data: "+str(data))

        # CASE FOR EVERY TYPE OF MESSAGE IN PROTOCOL
        # I would like to use a switch statement, but developing with python 3.9 (look into this)
        
        if msg_type == MessageTypes.HANDSHAKE_REQ:
            self.receieve_handshake(addr, session_id)

        if msg_type == MessageTypes.HANDSHAKE_ACK:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_ACK_2:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_FINAL_1:
            self.set_and_check_event(msg_type, addr, session_id, data)

        if msg_type == MessageTypes.HANDSHAKE_FINAL_2:
            self.set_and_check_event(msg_type, addr, session_id, data)
        
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
            if data: # temp_public_key|signature(temp_public_key)
                messages = data.split(self.delimiter)
                public_key_bytes = messages[0] # temp_public_key
                signature = messages[1] # signature(temp_public_key)
                public_key = self.crypt.public_key_from_bytes(public_key_bytes)
                self.crypt.rsa_verify_signature(signature, public_key_bytes, public_key)
                self.receive_key_exchange(addr, session_id, public_key)
            else: # no attached data
                self.receive_key_exchange(addr, session_id, None)
            

        if msg_type == MessageTypes.EXCHANGE_ACK:
            if data: # temp_public_key|signature(temp_public_key)
                messages = data.split(self.delimiter)
                public_key_bytes = messages[0] # temp_public_key
                signature = messages[1] # signature(temp_public_key)
                public_key = self.crypt.public_key_from_bytes(public_key_bytes)
                self.crypt.rsa_verify_signature(signature, public_key_bytes, public_key)
                self.set_and_check_event(msg_type, addr, session_id, public_key)
            else: # no attached data
                self.set_and_check_event(msg_type, addr, session_id, None)
            

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


    def _create_client(self, addr : str, port : int) -> client.Client:
        client_obj = client.Client(addr, port)
        self.clients.append(client_obj)
        return client_obj
    
    # Event funcs

    def _create_event(self, msg_type : int, addr : str, session_id : bytes) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            return self._get_event(msg_type, addr, session_id) # if event already exists, just return that
        if (msg_type, addr, session_id) not in self.listen_events:
            data = None
            self.listen_events[(msg_type, addr, session_id)] = [t.Event(), data] # create a new event for this specific connection
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
    
    def set_and_check_event(self, msg_type : int, addr : str, session_id : bytes, data: any) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self._set_data(msg_type, addr, session_id, data)
            self.listen_events[(msg_type, addr, session_id)][0].set() # set this event if it exists
            return True
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
                t_print("Event of type: "+str(msg_type)+" successful")
                self._remove_event(msg_type, addr, session_id)
                data = self._get_data(msg_type, addr, session_id)
                return data
            t_print("Event timed out of type: "+str(msg_type))
        else:
            t_print("Event failed of type: "+str(msg_type))
            return None # None if timeout, or event failed to be created

    def _send_message(self, addr : str, port : int, msg_type : int, session_id : bytes, payload : bytearray = None) -> bool:
        client_obj = self._create_client(addr, port)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if not payload:
            payload = bytearray()
        msg = create_message(payload, msg_type, session_id)
        return client_obj.send_message(msg)
        
    def _generate_session_id(self) -> bytes:
        return r.randbytes(8)

    ## Protocol Operations

    def request_handshake(self, addr : str, session_id : bytes = None) -> bool:
        # here we get our public key ready
        if (not session_id): # if session id not provided for this interaction, generate a new one
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_REQ, session_id) # Request handshake with target (payload will be the public key)
        self.wait_event(MessageTypes.HANDSHAKE_ACK, addr, session_id) # Create an event to block until response received
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_ACK_2, session_id)
        self.wait_event(MessageTypes.HANDSHAKE_FINAL_1, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_FINAL_2, session_id)
        t_print("Handshake finished!")
        return True

    def receieve_handshake(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_ACK, session_id)
        self.wait_event(MessageTypes.HANDSHAKE_ACK_2, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_FINAL_1, session_id)
        self.wait_event(MessageTypes.HANDSHAKE_FINAL_2, addr, session_id)
        t_print("Handshake finished!")
        return True
    
    def request_update_peers(self, addr : str, session_id : bytes = None) -> bool:
        if (not session_id):
            session_id = self._generate_session_id()
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_REQ, session_id)
        self.wait_event(MessageTypes.UPDATE_PEERS_ACK, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_ACK_2, session_id)
        self.wait_event(MessageTypes.UPDATE_PEERS_FINAL_1, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_FINAL_2, session_id)
        t_print("Update Peer Table finished!")
        return True
    
    def receive_update_peers(self, addr : str, session_id : bytes) -> bool:
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_ACK, session_id)
        self.wait_event(MessageTypes.UPDATE_PEERS_ACK_2, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.UPDATE_PEERS_FINAL_1, session_id)
        self.wait_event(MessageTypes.UPDATE_PEERS_FINAL_2, addr, session_id)
        t_print("Update Peer Table finished!")
        return True
    
    def request_key_exchange(self, addr: str, session_id : bytes = None) -> bool:
        if (not session_id):
            session_id = self._generate_session_id()
        # create the temporary public and private key for the exchange
        message = bytearray()
        message.extend(self.crypt.public_key_to_bytes(self.crypt.public_key))
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far
        message.extend(self.delimiter)
        message.extend(signature)
        self._send_message(addr, self.port, MessageTypes.EXCHANGE_REQ, session_id, message) # temp_public_key|signature(temp_public_key)
        peer_public_key = self.wait_event(MessageTypes.EXCHANGE_ACK, addr, session_id)
        if not peer_public_key:
            return False
        self._send_message(addr, self.port, MessageTypes.EXCHANGE_ACK_2, session_id)
        self.wait_event(MessageTypes.EXCHANGE_FINAL, addr, session_id)
        t_print("Key exchange finished!")
        return True
    
    def receive_key_exchange(self, addr : str, session_id : bytes, peer_public_key : RSAPublicKey) -> bool:
        if not peer_public_key:
            return False
        # encrypt our public key with the given temporary public key
        message = bytearray()
        message.extend(self.crypt.public_key_to_bytes(self.crypt.public_key))
        signature = self.crypt.rsa_generate_signature(message, self.crypt.private_key) # sign the message thus far
        message.extend(self.delimiter)
        message.extend(signature)
        self._send_message(addr, self.port, MessageTypes.EXCHANGE_ACK, session_id, message) # temp_public_key(public_key)|signature(temp_public_key(public_key))
        self.wait_event(MessageTypes.EXCHANGE_ACK_2, addr, session_id)
        self._send_message(addr, self.port, MessageTypes.EXCHANGE_FINAL, session_id)
        t_print("Key exchange finished!")
        return True

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
        self.stop() # stop the server
        for socket in self.clients:
            socket.exit()
        
        