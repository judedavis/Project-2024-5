from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h.start_server()
h.request_handshake('192.168.1.101')
h.request_update_peers('192.168.1.101')