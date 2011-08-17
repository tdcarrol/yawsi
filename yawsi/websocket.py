# -*- coding: utf-8 -*-
"""


"""

import functools
import socket
import urlparse

__all__ = ('websocket', 'WebSocketType')

_wraps_builtin = functools.partial(functools.wraps, updated = (),
                                   assigned = ('__name__', '__doc__'))

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

    @_wraps_builtin(socket.SocketType.accept)
    def accept(self):
        sock, addr = self._sock.accept()
        print 'ACCEPTED'

        http_method, self.path, http_version, headers = self._get_data(sock)
        version = headers.get('Sec-WebSocket-Version')
        print headers

        WSType = _WebSocketType._classes.get(version, WebSocketType)
        websocket = WSType(_sock = sock)
        websocket.server_handshake(http_method, self.path, http_version,
                                   headers)
        print 'HANDSHAKEN'

        return websocket, addr

    @_wraps_builtin(socket.SocketType.dup)
    def dup(self):
        return self.__class__(_sock = self._sock)

    @_wraps_builtin(socket.SocketType.connect)
    def connect(self, address):
        parsed = urlparse.urlsplit(address)
        # TODO

    def server_handshake(self, http_method, path, http_version, headers):
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

        def get_lines(sockfile):
            line = sockfile.readline()

            if not line or not line.strip():
                raise StopIteration

            yield line

        sockfile = sock.makefile()
        print 'GETTING LINES'
        lines = [line for line in get_lines(sockfile)]
        request = lines[0].split()

        if len(request) < 3:
            print request
            raise # TODO

        http_method, path, http_version = request

        headers = dict(self._parse_header(line) for line in lines[1:] if
                                          line.strip())
        return http_method, path, http_version, headers

    def _parse_header(self, line):
        raw_header, _, raw_value = line.partition(u':')

        header = raw_header.lower().strip()
        value = raw_value.strip()

        if not header:
            raise # TODO

        if not value:
            raise # TODO

        return header, value


websocket = WebSocketType = _WebSocket

class _WebSocketDraftHybi07(WebSocketType):
    version = '7'

    @functools.wraps(WebSocketType.server_handshake)
    def server_handshake(self, http_method, path, http_version, headers):
        print path, headers


@functools.wraps(socket.create_connection)
def create_connection(address, timeout = None, source_address = None):
    ws = websocket()
    ws.settimeout(timeout)
    ws.connect(address)

    return ws
