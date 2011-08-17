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
    sock, addr = s.accept()
    sys.stdout = sys.stderr = sock.makefile(bufsize = 0)
    x = sp.Popen(['/home/derek/x.sh'], stdout = sp.PIPE)

    for line in x.stdout:
        print line,
