# -*- coding: utf-8 -*-
"""


"""

import functools
import socket
import urlparse

__all__ = ('websocket', 'WebSocketType')

class _WebSocketType(type):
    """


    """

    def __init__(cls, name, bases, attrs):
        """


        """

        if not hasattr(_WebSocketType, '_classes'):
            _WebSocketType._classes = {}

        version = attrs.get('version')
        _WebSocketType._classes[version] = cls

        super(_WebSocketType, cls).__init__(name, bases, attrs)


class _WebSocket(socket.SocketType):
    """


    """

    __metaclass__ = _WebSocketType

    __doc__ = socket.SocketType.__doc__

    path = None

    @functools.wraps(socket.SocketType.accept)
    def accept(self):
        sock, addr = self._sock.accept()

        http_method, self.path, http_version, headers = self._get_data(sock)
        version = headers.get('Sec-WebSocket-Version')

        WSType = _WebSocketType._classes.get(version, WebSocketType)
        websocket = WSType(_sock = sock)
        websocket.handshake(http_method, self.path, http_version, headers)

        return websocket, addr

    @functools.wraps(socket.SocketType.dup)
    def dup(self):
        return self.__class__(_sock = self._sock)

    @functools.wraps(socket.SocketType.connect)
    def connect(self, address):
        parsed = urlparse.urlsplit(address)
        # TODO

    def server_handshake(self, headers):
        """


        """

        raise NotImplementedError

    def client_handshake(self, headers):
        """


        """

        raise NotImplementedError

    def _get_data(self, sock):
        """


        """

        sockfile = sock.makefile()
        lines = [line for line in sockfile]
        http_method, path, http_version = line[0].split()
        headers = dict(self._parse_header(line) for line in lines[1:])

        return http_method, path, http_version, headers

    def _parse_header(self, line):
        raw_header, raw_value = line.split(u':')

        header = raw_header.lower().strip()
        value = raw_value.strip()

        return header, value


websocket = WebSocketType = _WebSocket

class _WebSocketDraftHybi07(WebSocketType):
    version = '7'

    @functools.wraps(WebSocketType.server_handshake)
    def server_handshake(self, path, headers):
        pass


@functools.wraps(socket.create_connection)
def create_connection(address, timeout = None, source_address = None):
    ws = websocket()
    ws.settimeout(timeout)
    ws.connect(address)

    return ws
