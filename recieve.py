from scripts.hybrid import TCPHybrid
from scripts.shared import *
from time import sleep

h = TCPHybrid()
h.start_server()
addr, port = resolve_host('192.168.1.101', 38888)
h._create_client(addr, port)
h.request_join_network(addr)
h.send_no_op(addr)
h._create_client(addr, port)
h.request_keep_alive(addr)
h.request_send_data(addr, bytes(100))
# h.request_update_peers(addr)
# rows = h.peer_table.get_peers()
# for row in rows:
#     print(row[0])