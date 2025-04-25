from scripts.shared import *
import socket as s
import threading as t

class Server (SockObj):
    def __init__(self, port) -> None:
        self.addr = "0.0.0.0" # Arbitrary local address
        super().__init__(self.addr, port, True) # init SockObj
        self.bind() # bind to address and port

        self.stay_alive = True
        self.threads = {}

    def _find_local_addr (self) -> str:
        """
        Collects all ip addresses used by the host
        and asks the user to pick one to bind to
        """
        addrs = s.gethostbyname_ex(self.hostname)
        addrs = addrs[2]
        t_print("Which address would you like to bind to?")
        for i in range(0, len(addrs)):
            t_print(str(i)+" - "+addrs[i])
        num = input("\n")
        return addrs[int(num)]
    
    def _handle_peer(self, sock : s.socket, addr : list) -> None:
        connection_alive = True
        while self.stay_alive and connection_alive:
            connection_alive = self._handle_connection(sock, addr)

    def _handle_connection (self, sock) -> None:
        data = recv_msg(sock)
        t_print(data)
        t_print("Thread exiting")

    def receive_peers (self) -> None:
        self.sock.listen()
        t_print("listening on: "+self.addr+" on port: "+str(self.port))
        thread_count = 0

        while self.stay_alive:
            conn, addr = self.sock.accept()
            t_print("Incoming connection from "+str(addr[0])+" on port "+str(addr[1]))
            conn_thread = t.Thread(target=self._handle_peer, name="connnection-"+str(thread_count), args=[conn, addr])
            self.threads[conn_thread.ident] = conn_thread
            self.threads[conn_thread.ident].start()
            thread_count+=1

        t_print("shutting down")
        self.sock.shutdown(s.SHUT_RDWR)
        self.sock.close()

    def stop (self) -> None:
        self.stay_alive = False