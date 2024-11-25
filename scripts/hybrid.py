import threading as t
import scripts.client as client
import scripts.server as server
from scripts.shared import *

class TCPHybrid ():
    def __init__(self, port=38888):
        self.port = port
        self.server = server.Server(self.port)
        self.clients = []
        self.threads = []

    def start_server(self):
        self.threads.append(t.Thread(target=self.server.receive_peers,
                                     name="Server Thread"))
        self.threads[len(self.threads)-1].start()

    def send_message(self, data, addr, port):
        self.clients.append(client.Client(addr, port, data))
        self.threads.append(t.Thread(target=self.clients[len(self.clients)-1],
                                     name="client "+str(len(self.clients))))