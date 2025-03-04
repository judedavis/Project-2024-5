import threading as t
import scripts.client as client
from scripts.server import Server
from scripts.shared import *

class TCPHybrid (Server):
    def __init__(self, port=38888) -> None:
        super().__init__(port)
        self.clients = []
        self.listen_events = {}

    # OVERRIDDEN
    def _handle_connection(self, sock : s.socket, addr : int) -> None:
        msg_len, msg_type, data = recv_msg(sock)
        addr = sock.getpeername()

        return

    def start_server(self) -> None:
        server_thread = t.Thread(target=self.receive_peers,
                                     name="Server Thread")
        self.threads[server_thread.ident] = server_thread
        self.threads[server_thread.ident].start()


    def _create_client(self, addr : str, port : int) -> client.Client:
        client_obj = client.Client(addr, port)
        # client_thread = t.Thread(target=method,
        #                              name="client "+str(len(self.clients)+1))
        self.clients.append(client_obj)
        # self.threads[client_thread.ident] = client_thread
        return client_obj
    
    def _send_message(self, addr : str, port : int, msg_type : int, payload = None) -> bool:
        client_obj = self._create_client(addr, port)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        msg = create_message(payload, msg_type)
        return client_obj.send_message(msg)
    
    def _create_event(self, msg_type : int, addr : str, port : int) -> bool:
        if (msg_type, addr, port) not in self.listen_events:
            data = None
            self.listen_events[(msg_type, addr, port)] = (t.Event(), data) # create a new event for this specific connection
            return True
        return False
    
    def _check_event(self, msg_type : int, addr : str, port : int) -> bool:
        if (msg_type, addr, port) in self.listen_events:
            self.listen_events[(msg_type, addr, port)][0].set() # set this event if it exists
            return True
        return False
    
    def _remove_event(self, msg_type : int, addr : str, port : int) -> bool:
        if (msg_type, addr, port) in self.listen_events:
            self.listen_events.pop((msg_type, addr, port))
            return True
        return False

    def handshake(self, addr : str, port : int):
        # here we get our public key ready
        self._send_message(addr, port, MessageTypes.HANDSHAKE) # Request handshake with target (payload will be the public key)
        self._create_event(1, addr, port)
        # wait on event


    def exit(self) -> None:
        self.stop() # stop the server
        for socket in self.clients:
            socket.exit()
        
        