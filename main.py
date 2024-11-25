import tkinter as tk
import threading as t
import scripts.hybrid as hybrid

class Window ():
    def __init__(self):
        self.wh = [500,500]

        self.window = tk.Tk()
        self.window.config(highlightbackground='black', width=self.wh[0], height=self.wh[1])
        self.logic_thread = None
        self.tcp_hybrid = hybrid.TCPHybrid()

    def _background_logic(self):
        self.tcp_hybrid.start_server()

    def run(self):
        self.logic_thread = t.Thread(target=self._background_logic, name="TCP Thread")
        self.logic_thread.daemon = True
        self.logic_thread.start()
        self.window.mainloop()


window = Window()
window.run()