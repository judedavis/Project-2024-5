from scripts.hybrid import TCPHybrid
from scripts.shared import *
from time import sleep

h = TCPHybrid()
h.start_server()
addr, port = resolve_host('guadalajara.ddnsking.com', 38888)
h._create_client(addr, port)
session_id = h._generate_session_id()
h.request_join_network(addr, session_id)
h.request_keep_alive(addr, session_id)
h.request_send_data(addr, bytes(100), session_id)
h.send_no_op(addr, session_id)
# h.request_update_peers(addr)
# rows = h.peer_table.get_peers()
# for row in rows:
#     print(row[0])