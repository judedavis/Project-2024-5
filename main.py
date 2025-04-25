import tkinter as tk
import threading as t
import scripts.hybrid as hybrid
from scripts.shared import *
from time import sleep

class Window ():
    def __init__(self, headless=False):
        # Init the tcp hybrid
        self.tcp_hybrid = hybrid.TCPHybrid()
        self.logic_thread = None
        # Set up the GUI
        self.headless = headless
        if not self.headless: # if not headless then start the GUI
            self.wh = [500,500]
            self.window = tk.Tk()
            self.window.config(highlightbackground='black', width=self.wh[0], height=self.wh[1])
            # Set up gui elements
            self.elements = {}
            self.elements['title_lbl'] = tk.Label(self.window, text='Decentralised Chat Application',height=2)
            self.elements['title_lbl'].pack()
            self.elements['address_inp_lbl'] = tk.Label(self.window, text='Please input the address of entrypoint:')
            self.elements['address_inp_lbl'].pack()
            self.elements['address_inp_txt'] = tk.Text(self.window, height=1, width=20)
            self.elements['address_inp_txt'].pack()
            self.elements['address_inp_btn'] = tk.Button(self.window, text='Connect to entrypoint', command=self._background_logic)
            self.elements['address_inp_btn'].pack()
            self.elements['address_inp_response'] = tk.Label(self.window, text='')
            self.elements['address_inp_response'].pack()

            self.window.protocol('WM_DELETE_WINDOW', self.kill_window)
            self.window.mainloop()
        else: # if headless just start the server
            self._background_logic()
        

    def _background_logic(self):
        if not self.headless:
            # Resolve the given address
            addr, port = resolve_host(self.elements['address_inp_txt'].get('1.0', 'end-1c'), self.tcp_hybrid.port)
            if addr == None or port == None: # if host wasn't resolved, show error message and return
                self.elements['address_inp_response'].config(text="Invalid address given, or host couldn't be resolved.")
                return
            # start the server
            self.tcp_hybrid.start_server()
            # create a fresh client for the connection and request to join their network
            self.tcp_hybrid._create_client(addr,port)
            self.tcp_hybrid.request_join_network(addr)
            self.elements['address_inp_response'].config(text="Successfully connected.")
        else:
            # start the server
            self.tcp_hybrid.start_server()
        while self.tcp_hybrid.stay_alive:
            self.tcp_hybrid.query_peers()
            sleep(self.tcp_hybrid.keep_alive_timeout)
        
    def kill_window(self):
        self.tcp_hybrid.exit()
        self.window.destroy()



window = Window()