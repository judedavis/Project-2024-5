from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h.start_server()
h.request_key_exchange('192.168.1.101')