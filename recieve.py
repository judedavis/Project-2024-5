from scripts.hybrid import TCPHybrid
from scripts.shared import *

h = TCPHybrid()
# h.start_server()
# addr, port = resolve_host('guadalajara.ddnsking.com', 38888)
# h._create_client(addr, port)
# h.request_handshake(addr)
rows = h.peer_table.get_peers()
for row in rows:
    print(row[0])