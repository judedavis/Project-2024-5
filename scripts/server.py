from scripts.shared import *
import socket as s
import threading as t

class Server (SockObj):
    def __init__(self, port):
        self.addr = "0.0.0.0" # Arbitrary local address
        self.port = port
        super().__init__(self.addr, self.port, True) # init SockObj
        self.bind() # bind to address and port

        self.stay_alive = True
        self.threads = []

    def _find_local_addr (self):
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

    def _handle_connection (self, sock):
        data = recv_msg(sock)
        t_print(data)
        t_print("Thread exiting")

    def receive_peers (self):
        self.sock.listen()
        t_print("listening on: "+self.addr+" on port: "+str(self.port))
        thread_count = 0

        while self.stay_alive:
            conn, addr = self.sock.accept()
            t_print("Incoming connection from "+str(addr[0])+" on port "+str(addr[1]))
            conn_thread = t.Thread(target=self._handle_connection, name="connnection-"+str(thread_count), args=[conn])
            self.threads.append(conn_thread)
            self.threads[len(self.threads)-1].start()
            thread_count+=1

        t_print("shutting down")
        self.sock.shutdown(s.SHUT_RDWR)
        self.sock.close()

    def exit (self):
        self.stay_alive = False