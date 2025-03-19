from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
h.start_server()
h.request_join_network('192.168.1.101')
h.request_keep_alive('192.168.1.101')
h.request_send_data('192.168.1.101')