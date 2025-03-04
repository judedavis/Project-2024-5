from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h._send_message('localhost', 38888, MessageTypes.HANDSHAKE, "FUCKY OU")