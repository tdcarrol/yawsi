# -*- coding: utf-8 -*-
"""


"""

import socket
import subprocess as sp
import sys

import yawsi.websocket as ws

s = ws.websocket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(('localhost', 8888))
s.listen(1)

while 1:
    conn, addr = s.accept()
    sys.stdout = conn.makefile(bufsize = 0)
    x = sp.Popen(['/bin/ls', '/'], stdout = sp.PIPE)

    for line in x.stdout:
        print line,

    conn.close()
