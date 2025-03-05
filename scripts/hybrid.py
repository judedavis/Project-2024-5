import threading as t
import scripts.client as client
from scripts.server import Server
from scripts.shared import *
import random as r # good or bad?

class TCPHybrid (Server):
    def __init__(self, port=38888) -> None:
        super().__init__(port)
        self.clients = []
        self.listen_events = {}

    # OVERRIDDEN
    def _handle_connection(self, sock : s.socket, addr : list) -> None:
        addr = addr[0]
        msg_len, msg_type, session_id, data = recv_msg(sock)

        if data:
            t_print("received message of type: "+str(msg_type))
        else:
            t_print("received message of type: "+str(msg_type)+" with data: "+str(data))
        if msg_type == MessageTypes.HANDSHAKE_REQ:
            self.receieve_handshake(addr, session_id)
        return

    def _create_client(self, addr : str, port : int) -> client.Client:
        client_obj = client.Client(addr, port)
        # client_thread = t.Thread(target=method,
        #                              name="client "+str(len(self.clients)+1))
        self.clients.append(client_obj)
        # self.threads[client_thread.ident] = client_thread
        return client_obj
    
    def _send_message(self, addr : str, port : int, msg_type : int, session_id : int, payload = None) -> bool:
        client_obj = self._create_client(addr, port)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if not payload:
            payload = bytearray()
        msg = create_message(payload, msg_type, session_id)
        return client_obj.send_message(msg)
    
    def _get_event(self, msg_type : int, addr : str, session_id : int) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            return self.listen_events[(msg_type, addr, session_id)] # get and return the event
        return False

    def _create_event(self, msg_type : int, addr : str, session_id : int) -> t.Event:
        if (msg_type, addr, session_id) not in self.listen_events:
            self.listen_events[(msg_type, addr, session_id)] = t.Event() # create a new event for this specific connection
            return self._get_event(msg_type, addr, session_id)
        return False
    
    def _check_event(self, msg_type : int, addr : str, session_id : int) -> t.Event:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events[(msg_type, addr, session_id)][0].set() # set this event if it exists
            return self._get_event(msg_type, addr, session_id)
        return False
    
    def _remove_event(self, msg_type : int, addr : str, session_id : int) -> bool:
        if (msg_type, addr, session_id) in self.listen_events:
            self.listen_events.pop((msg_type, addr, session_id))
            return True
        return False
    
    def _generate_session_id(self) -> int:
        return int.from_bytes(r.randbytes(8), 'little')

    def request_handshake(self, addr : str, port : int):
        # here we get our public key ready
        session_id = self._generate_session_id()
        self._send_message(addr, port, MessageTypes.HANDSHAKE_REQ, session_id) # Request handshake with target (payload will be the public key)
        event = self._create_event(MessageTypes.HANDSHAKE_ACK, addr, session_id) # Create an event to block until response received
        if event:
            t_print("event was created")
            event.wait()
            t_print("the event was satisfied")
        else:
            t_print("event was not created")
        # wait on event

    def receieve_handshake(self, addr: str, session_id : int):
        self._send_message(addr, self.port, MessageTypes.HANDSHAKE_ACK, session_id)
        return
    
    def start_server(self) -> None:
        server_thread = t.Thread(target=self.receive_peers,
                                     name="Server Thread")
        self.threads[server_thread.ident] = server_thread
        self.threads[server_thread.ident].start()

    def exit(self) -> None:
        self.stop() # stop the server
        for socket in self.clients:
            socket.exit()
        
        