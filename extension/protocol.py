"""
Custom protocol implementations for the MITM proxy.
"""
import asyncio
import ssl
from typing import Tuple, Optional


from mitm.core import Connection, Flow, Host, InvalidProtocol, Protocol
from mitm.httpq import Request, Response


async def tls_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_side: bool = False,
):
    """
    Manually perform a TLS handshake over a stream.

    Args:
        reader: The reader of the client connection.
        writer: The writer of the client connection.
        ssl_context: The SSL context to use. Defaults to None.
        server_side: Whether the connection is server-side or not. Defaults to False.

    Note:
        If the `ssl_context` is not passed and `server_side` is not set, then
        `ssl.create_default_context()` will be used.

        For Python 3.6 to 3.9 you can use `ssl.PROTOCOL_TLS` for the SSL context. For
        Python 3.10+ you need to either use `ssl.PROTOCOL_TLS_CLIENT` or
        `ssl.PROTOCOL_TLS_SERVER` depending on the role of the reader/writer.

    Example:

        Client code:

        .. code-block:: python

            from toolbox.asyncio.streams import tls_handshake
            import asyncio

            async def client():
                reader, writer = await asyncio.open_connection("httpbin.org", 443, ssl=False)
                await tls_handshake(reader=reader, writer=writer)

                # Communication is now encrypted.
                ...

            asyncio.run(client())

        Server code:

        .. code-block:: python

            from toolbox.asyncio.streams import tls_handshake
            import asyncio
            import ssl

            async def server(reader, writer):
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile="server.crt", keyfile="server.key")
                await tls_handshake(
                    reader=reader,
                    writer=writer,
                    ssl_context=context,
                    server_side=True,
                )

                # Connection is now encrypted.
                ...

            async def main():
                srv = await asyncio.start_server(server, host="127.0.0.1", port=8888)
                async with srv:
                    await srv.serve_forever()

            asyncio.run(main())
    """

    if not server_side and not ssl_context:
        ssl_context = ssl.create_default_context()

    transport = writer.transport
    protocol = transport.get_protocol()

    loop = asyncio.get_event_loop()
    new_transport = await loop.start_tls(
        transport=transport,
        protocol=protocol,
        sslcontext=ssl_context,
        server_side=server_side,
    )

    reader._transport = new_transport
    writer._transport = new_transport

class HTTP(Protocol):
    """
    Adds support for HTTP protocol (with TLS support).

    This protocol adds HTTP and HTTPS proxy support to the `mitm`. Note that by
    "HTTPS proxy" we mean a proxy that supports the `CONNECT` statement, and not
    one that instantly performs a TLS handshake on connection with the client (though
    this can be added if needed).

    `bytes_needed` is set to 8192 to ensure we can read the first line of the request.
    The HTTP/1.1 protocol does not define a minimum length for the first line, so we
    use the largest number found in other projects.
    """

    bytes_needed: int = 8192 *1000
    buffer_size: int = 8192 *1000
    timeout: int = 15
    keep_alive: bool = True

    async def resolve(self, connection: Connection, data: bytes) -> Tuple[str, int, bool]:
        """
        Resolves the destination server for the protocol.

        Args:
            connection: Connection object containing a client host.
            data: The initial incoming data from the client.

        Returns:
            A tuple containing the host, port, and bool if the connection is encrypted.

        Raises:
            InvalidProtocol: If the connection failed.
        """
        try:
            request = Request.parse(data)

            # Deal with 'CONNECT'.
            tls = False
            if request.method == b"CONNECT":
                tls = True

                # Get the hostname and port.
                if not request.target:
                    raise InvalidProtocol
                host, port = request.target.decode().split(":")

            # Deal with any other HTTP method.
            elif request.method:

                # Get the hostname and port.
                if b"host" not in request.headers:
                    raise InvalidProtocol
                host, port = request.headers[b"host"].decode(), 80

            # Unable to parse the request.
            elif not request.method:
                raise InvalidProtocol
        except:  # pragma: no cover  # noqa: E722
            raise InvalidProtocol  # pylint: disable=raise-missing-from

        return host, int(port), tls

    async def connect(self, connection: Connection, host: str, port: int, tls: bool, data: bytes):
        """
        Connects to the destination server if the data is a valid HTTP request.

        Args:
            connection: The connection to the destination server.
            host: The hostname of the destination server.
            port: The port of the destination server.
            tls: Whether the connection is encrypted.
            data: The initial data received from the client.

        Raises:
            InvalidProtocol: If the connection failed.
        """

        # Generate certificate if TLS.
        if tls:

            # Accept client connection.
            connection.client.writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await connection.client.writer.drain()

            # Generates new context specific to the host.
            ssl_context = self.certificate_authority.new_context(host)

            # Perform handshake.
            try:
                await tls_handshake(
                    reader=connection.client.reader,
                    writer=connection.client.writer,
                    ssl_context=ssl_context,
                    server_side=True,
                )
            except ssl.SSLError as err:
                raise InvalidProtocol from err

        # Connect to the destination server and send the initial request.
        reader, writer = await asyncio.open_connection(
            host=host,
            port=port,
            ssl=tls,
        )
        connection.server = Host(reader, writer)

        # Send initial request if not SSL/TLS connection.
        if not tls:
            connection.server.writer.write(data)
            await connection.server.writer.drain()

    async def handle(self, connection: Connection):
        """
        Handles the connection between a client and a server.

        Args:
            connection: Client/server connection to relay.
        """

        # Keeps the connection alive until the client or server closes it.
        run_once = True
        while (
            not connection.client.reader.at_eof()
            and not connection.server.reader.at_eof()
            and (self.keep_alive or run_once)
        ):

            # Keeps trying to relay data until the connection closes.
            event = asyncio.Event()
            await asyncio.gather(
                self.relay(connection, event, Flow.SERVER_TO_CLIENT),
                self.relay(connection, event, Flow.CLIENT_TO_SERVER),
            )

            # Run the while loop only one iteration if keep_alive is False.
            run_once = False

    async def relay(self, connection: Connection, event: asyncio.Event, flow: Flow):
        """
        Relays HTTP data between the client and the server.

        Args:
            connection: Client/server connection to relay.
            event: Event to wait on.
            flow: The flow to relay.
        """

        if flow == Flow.CLIENT_TO_SERVER:
            reader = connection.client.reader
            writer = connection.server.writer
        elif flow == Flow.SERVER_TO_CLIENT:
            reader = connection.server.reader
            writer = connection.client.writer
        data_block = b''
        content_length = 0
        request = None
        while not event.is_set() and not reader.at_eof():
            data = None
            try:
                data = await asyncio.wait_for(
                    reader.read(self.buffer_size),
                    timeout=self.timeout,
                )
            except asyncio.exceptions.TimeoutError:
                pass

            if not data:
                event.set()
                break

            if flow == Flow.CLIENT_TO_SERVER:
                request = Request.parse(data)
                connection.request = request
            if b'CONNECT' != connection.request.method: # 忽略CONNECT代理，无意义
                # Pass data through middlewares.
                for middleware in self.middlewares:
                    if flow == Flow.SERVER_TO_CLIENT:
                        if data.startswith(b"HTTP"):
                            if data.endswith(b"0\r\n\r\n"): # 响应数据结束
                                data = await middleware.server_data(connection, data)
                            else:
                                data_block = data
                                resp = Response.parse(data)
                                content_length = int(resp.headers.get(b'content-length', b'0'))
                                transfer_encoding = resp.headers.get(b'transfer-encoding', b'').decode()
                                if content_length > 0 or transfer_encoding: # 响应数据还未结束
                                    pass
                                else:
                                    data = await middleware.server_data(connection, data_block)
                        else:
                            data_block = data_block + data
                        # data = await middleware.server_data(connection, data)
                    elif flow == Flow.CLIENT_TO_SERVER:
                        data = await middleware.client_data(connection, data)

            writer.write(data)
            await writer.drain()
