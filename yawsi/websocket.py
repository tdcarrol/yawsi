# -*- coding: utf-8 -*-
"""


"""

import base64
import functools
import hashlib
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

    def __init__(self, family = socket.AF_INET, type = socket.SOCK_STREAM,
                 proto = 0, _sock = None):
        if _sock is None:
            _sock = socket._realsocket(family, type, proto)

        self._sock = _sock

        for method in socket._delegate_methods:
            if not hasattr(self, method):
                setattr(self, method, getattr(_sock, method))

    @_wraps_builtin(socket.SocketType.accept)
    def accept(self):
        sock, addr = self._sock.accept()

        http_method, self.path, http_version, headers = self._get_data(sock)
        version = headers.get('sec-websocket-version')

        WSType = _WebSocketType._classes.get(version, WebSocketType)
        websocket = WSType(_sock = sock)
        websocket.server_handshake(http_method, self.path, http_version,
                                   headers)

        return websocket, addr

    @_wraps_builtin(socket.SocketType.dup)
    def dup(self):
        return self.__class__(_sock = self._sock)

    @_wraps_builtin(socket.SocketType.connect)
    def connect(self, address):
        parsed = urlparse.urlsplit(address)
        # TODO

    @_wraps_builtin(socket.SocketType.makefile)
    def makefile(self, mode = 'r', bufsize = -1):
        return socket._fileobject(self, mode, bufsize)

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

        def get_lines():
            sockfile = sock.makefile()

            while 1:
                line = sockfile.readline()

                if not line or not line.strip():
                    raise StopIteration

                yield line.strip()

        lines = [line for line in get_lines()]
        request = lines[0].split()

        if len(request) < 3:
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
    _GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    _SERVER_HANDSHAKE = (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Accept: %(key)s\r\n'
        '\r\n'
    )

    @functools.wraps(WebSocketType.server_handshake)
    def server_handshake(self, http_method, path, http_version, headers):
        client_key = headers['sec-websocket-key']
        hash = hashlib.sha1(client_key + self._GUID).digest()
        key = base64.b64encode(hash)

        handshake = self._SERVER_HANDSHAKE % {'key': key}
        self._sock.send(handshake)

    @_wraps_builtin(WebSocketType.close)
    def close(self):
        # TODO: Close correctly.
        self._sock.send('\x88')
        self._sock.close()

    @_wraps_builtin(WebSocketType.send)
    def send(self, data, flags = 0):
        data = data.encode('utf-8')
        payload_len = self._get_payload_length(data)
        packet = '\x81' + payload_len + data

        return self._sock.send(packet)

    @_wraps_builtin(WebSocketType.sendall)
    def sendall(self, data, flags = 0):
        if isinstance(data, memoryview):
            data = data.tobytes()

        self.send(data, flags)
        # TODO: Fragmenting

    def _get_payload_length(self, data):
        sz = len(data)

        if sz <= 125:
            payload_len = chr(sz)
        elif sz <= 65535:
            payload_len = chr(126) + chr(sz >> 8) + chr(sz & 0xFF)
        else:
            payload_len = chr(127)
            # TODO: Fragmenting?

        return payload_len


@functools.wraps(socket.create_connection)
def create_connection(address, timeout = None, source_address = None):
    ws = websocket()
    ws.settimeout(timeout)
    ws.connect(address)

    return ws
