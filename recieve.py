from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h.start_server()
addr, port = resolve_host('guadalajara.ddnsking.com', 38888)
h.request_handshake(addr)