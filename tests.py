# -*- coding: utf-8 -*-
"""


"""

import yawsi.websocket as ws
import socket

s = ws.websocket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(('localhost', 8888))
s.listen(1)
sock, addr = s.accept()
s.close()