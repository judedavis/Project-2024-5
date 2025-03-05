from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h.start_server()
h.request_handshake('localhost', h.port)