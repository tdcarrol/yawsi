# -*- coding: utf-8 -*-
"""


"""

import base64
import functools
import hashlib
import types
import urlparse

try:
    from gevent import socket
    from gevent import ssl
except ImportError:
    import socket
    import ssl

__all__ = ('websocket', 'WebSocketType', 'WEBSOCK_VERSION_DRAFT_HIXIE_75',
           'WEBSOCK_VERSION_DRAFT_HIXIE_76', 'WEBSOCK_VERSION_DRAFT_HYBI_00',
           'WEBSOCK_VERSION_DRAFT_HYBI_07', 'WEBSOCK_VERSION_DRAFT_HYBI_10')

WEBSOCK_VERSION_DRAFT_HIXIE_75 = '75'
WEBSOCK_VERSION_DRAFT_HYBI_00 = WEBSOCK_VERSION_DRAFT_HIXIE_76 = '0'
WEBSOCK_VERSION_DRAFT_HYBI_07 = '7'
WEBSOCK_VERSION_DRAFT_HYBI_10 = '10'

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
    __doc__ = socket.SocketType.__doc__

    __metaclass__ = _WebSocketType

    path = None

    def __init__(self, family = socket.AF_INET, type = socket.SOCK_STREAM,
                 proto = 0, _sock = None):
        super(_WebSocket, self).__init__(family, type, proto, _sock)
        self._rebind_delegates()

    def _rebind_delegates(self):
        for method in socket._delegate_methods:
            if hasattr(self.__class__, method):
                cls_method = getattr(self.__class__, method)
                bound_method = types.MethodType(cls_method, self,
                                                self.__class__)
                setattr(self, method, bound_method)

    @_wraps_builtin(socket.SocketType.accept)
    def accept(self):
        conn, addr = super(self.__class__, self).accept()
        websocket = self._get_protocol_websocket(conn)

        return websocket, addr

    @classmethod
    def _get_protocol_websocket(cls, conn):
        data = cls.__get_data(conn)
        http_method, request_uri, http_version, headers = data
        version = cls.__get_version(headers)

        WSType = _WebSocketType._classes.get(version, WebSocketType)
        websocket = WSType(_sock = conn)
        websocket.request_uri = request_uri
        websocket._server_handshake(http_method, websocket.request_uri,
                                    http_version, headers)

        return websocket

    @_wraps_builtin(socket.SocketType.dup)
    def dup(self):
        return self.__class__(_sock = self._sock)

    @_wraps_builtin(socket.SocketType.connect)
    def connect(self, address):
        parsed = urlparse.urlsplit(address)
        # TODO

    def makefile(self, mode = 'r', bufsize = -1):
        return socket._fileobject(self, mode, bufsize)

    def _server_handshake(self, http_method, path, http_version, headers):
        """


        """

        raise NotImplementedError

    def _client_handshake(self, headers):
        """


        """

        raise NotImplementedError

    @classmethod
    def __get_version(cls, headers):
        version = headers.get('sec-websocket-version')

        if not version and 'sec-websocket-key1' in headers:
            return WEBSOCK_VERSION_DRAFT_HYBI_00

        return version

    @classmethod
    def __get_data(cls, conn):
        """


        """

        def get_lines():
            sockfile = conn.makefile()

            while 1:
                line = sockfile.readline()

                if not line or not line.strip():
                    raise StopIteration

                yield line.strip()

        lines = [line for line in get_lines()]
        request = lines[0].split()

        if len(request) < 3:
            raise # TODO

        http_method, request_uri, http_version = request
        headers = dict(cls.__parse_header(line) for line in lines[1:] if
                                         line.strip())

        return http_method, request_uri, http_version, headers

    @classmethod
    def __parse_header(cls, line):
        raw_header, _, raw_value = line.partition(u':')

        header = raw_header.lower().strip()
        value = raw_value.strip()

        if not header:
            raise # TODO

        if not value:
            raise # TODO

        return header, value


websocket = WebSocketType = _WebSocket

class _WebSocketDraftHybi00(WebSocketType):
    version = WEBSOCK_VERSION_DRAFT_HYBI_00

    @functools.wraps(WebSocketType._server_handshake)
    def _server_handshake(self, http_method, path, http_version, headers):
        pass

    @_wraps_builtin(WebSocketType.close)
    def close(self):
        pass

    @_wraps_builtin(WebSocketType.send)
    def send(self, data, flags = 0):
        pass


class _WebSocketDraftHybi07(WebSocketType):
    version = WEBSOCK_VERSION_DRAFT_HYBI_07

    _GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    _SERVER_HANDSHAKE = (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Accept: %(key)s\r\n'
        '\r\n'
    )

    @functools.wraps(WebSocketType._server_handshake)
    def _server_handshake(self, http_method, path, http_version, headers):
        client_key = headers['sec-websocket-key']
        hashed_key = hashlib.sha1(client_key + self._GUID).digest()
        key = base64.b64encode(hashed_key)

        handshake = self._SERVER_HANDSHAKE % {'key': key}
        super(self.__class__, self).send(handshake)

    @_wraps_builtin(WebSocketType.close)
    def close(self):
        # TODO: Close correctly.
        super(self.__class__, self).send('\x88')
        super(self.__class__, self).close()

    @_wraps_builtin(WebSocketType.send)
    def send(self, data, flags = 0):
        if isinstance(data, memoryview):
            data = data.tobytes()

        data = data.encode('utf-8')
        payload_len = self._get_payload_length(data)
        packet = '\x81' + payload_len + data

        return super(self.__class__, self).send(packet)

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


def create_websocket_from_connection(conn):
    return WebSocketType._get_protocol_websocket(conn)

@functools.wraps(socket.create_connection)
def create_connection(address, timeout = None, source_address = None):
    ws = websocket()
    ws.settimeout(timeout)
    ws.connect(address)

    return ws
