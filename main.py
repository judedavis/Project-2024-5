import tkinter as tk
from tkinter.ttk import *
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
        self.messages = {}
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
            self.elements['address_inp_txt'] = tk.Text(self.window, height=1, width=30)
            self.elements['address_inp_txt'].pack()
            self.elements['address_inp_btn'] = tk.Button(self.window, text='Connect to entrypoint', command=self._run)
            self.elements['address_inp_btn'].pack()
            self.elements['address_inp_response'] = tk.Label(self.window, text='Not connected.')
            self.elements['address_inp_response'].pack()
            self.elements['user_combobox_var'] = tk.StringVar()
            self.elements['user_combobox'] = Combobox(self.window, textvariable=self.elements['user_combobox_var'])
            self.elements['user_combobox'].pack()
            # populate the combobox
            idents = self.tcp_hybrid.peer_table.get_peer_idents()
            new_var = ()
            for ident in idents:
                ident = ident[0]
                new_var = new_var + (ident,)
            self.elements['user_combobox']['values'] = new_var
            self.elements['message_box_lbl'] = tk.Label(self.window, text='', height=20, width=40, borderwidth=2, relief="sunken", justify="left")
            self.elements['message_box_lbl'].pack()
            self.elements['message_inp_txt'] = tk.Text(self.window, height=2, width=40)
            self.elements['message_inp_txt'].pack()
            self.elements['message_inp_btn'] = tk.Button(self.window, text='Send Message', command=self.send_message)
            self.elements['message_inp_btn'].pack()
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
            idents = self.tcp_hybrid.peer_table.get_peer_idents()
            new_var = ()
            for ident in idents:
                ident = ident[0]
                new_var = new_var + (ident,)
            self.elements['user_combobox']['values'] = new_var
            for message in self.tcp_hybrid.received_messages:
                ident = message[0]
                msg = 'Them: '+message[1]
                if ident not in self.messages.keys():
                    self.messages[ident] = [msg]
                else:
                    self.messages[ident].append(msg)
            self.render_messages(self.elements['user_combobox'].get())
            sleep(self.tcp_hybrid.keep_alive_timeout)
    
    def render_messages(self, ident):
        message_str = ''
        for message in self.messages[ident]:
            message_str+=message+'\n\n'
        self.elements['message_box_lbl'].config(text=message_str)

    def send_message(self):
        message = self.elements['message_inp_txt'].get('1.0', 'end-1c')
        message_bytes = bytes(message.encode('utf-8'))
        ident = self.elements['user_combobox'].get()
        addr = self.tcp_hybrid.peer_table.get_user_last_address(ident)
        self.tcp_hybrid.request_send_data(addr, message_bytes)
        message = 'You: '+message
        if ident not in self.messages.keys():
            self.messages[ident] = [message]
        else:
            self.messages[ident].append(message)
        self.render_messages(ident)
        #self.tcp_hybrid.request_send_data()

    def _run(self):
        self.logic_thread = t.Thread(target=self._background_logic, name='client_thread')
        self.logic_thread.start()
        

    def kill_window(self):
        self.tcp_hybrid.exit()
        self.window.destroy()

