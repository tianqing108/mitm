"""
Man-in-the-middle.
"""

import asyncio
import logging
from typing import List, Optional, Any

from mitm import __data__
from mitm.core import Connection, Host, Middleware, Protocol
from mitm.coroutine import Coroutine
from mitm.crypto import CertificateAuthority
from mitm.extension.protocol import HTTP, InvalidProtocol

logger = logging.getLogger(__package__)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)


class MITM(Coroutine):
    """
    Man-in-the-middle server.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        protocols: Optional[List[type[Protocol]]] = None,
        middlewares: Optional[List[Middleware]] = None,
        certificate_authority: Optional[CertificateAuthority] = None,
        run: bool = False,
    ):
        """
        Initializes the MITM class.

        Args:
            host: Host to listen on. Defaults to `127.0.0.1`.
            port: Port to listen on. Defaults to `8888`.
            protocols: List of protocols to use. Defaults to `[protocol.HTTP]`.
            middlewares: List of middlewares to use. Defaults to `[middleware.Log]`.
            certificate_authority: Certificate authority to use. Defaults to `CertificateAuthority()`.
            run: Whether to start the server immediately. Defaults to `False`.

        Example:

            .. code-block:: python

                from mitm import MITM

                mitm = MITM()
                mitm.run()
        """
        self.host = host
        self.port = port
        self.certificate_authority = certificate_authority if certificate_authority else CertificateAuthority()

        # Stores the CA certificate and private key.
        cert_path, key_path = __data__ / "mitm.crt", __data__ / "mitm.key"
        self.certificate_authority.save(cert_path=cert_path, key_path=key_path)

        # Initialize any middleware that is not already initialized.
        middlewares = middlewares
        new_middlewares = []
        for middleware in middlewares:
            if isinstance(middleware, type):
                middleware = middleware()
            new_middlewares.append(middleware)
        self.middlewares = new_middlewares

        # Initialize any protocol that is not already initialized.
        protocols = protocols if protocols else [HTTP]
        new_protocols = []
        for protocol in protocols:
            if isinstance(protocol, type):
                protocol = protocol(certificate_authority=self.certificate_authority, middlewares=self.middlewares)
            new_protocols.append(protocol)
        self.protocols = new_protocols
        self.stop_event = asyncio.Event()

        super().__init__(run=run)

    async def entry(self):  # pragma: no cover
        """
        Entry point for the MITM class.
        """
        try:
            self.server = await asyncio.start_server(
                lambda reader, writer: self.mitm(
                    Connection(
                        client=Host(reader=reader, writer=writer),
                        server=Host(),
                    )
                ),
                host=self.host,
                port=self.port,
            )
        except OSError as err:
            self._loop.stop()
            raise err

        for middleware in self.middlewares:
            await middleware.mitm_started(host=self.host, port=self.port)

        async with self.server:
            try:
                await self.server.serve_forever()
            except asyncio.CancelledError:
                logger.debug("代理服务退出")
                self.server.close()

    async def mitm(self, connection: Connection):
        """
        Handles an incoming connection (single connection).

        Warning:
            This method is not intended to be called directly.
        """

        #  Calls middlewares for client initial connect.
        for middleware in self.middlewares:
            await middleware.client_connected(connection=connection)

        # Gets the bytes needed to identify the protocol.
        min_bytes_needed = max(proto.bytes_needed for proto in self.protocols)
        data = await connection.client.reader.read(n=min_bytes_needed)

        # Calls middleware on client's data.
        for middleware in self.middlewares:
            data = await middleware.client_data(connection=connection, data=data)

        # Finds the protocol that matches the data.
        proto = None
        for prtcl in self.protocols:
            proto = prtcl
            try:
                # Attempts to resolve the protocol, and connect to the server.
                host, port, tls = await proto.resolve(connection=connection, data=data)
                await proto.connect(connection=connection, host=host, port=port, tls=tls, data=data)
            except InvalidProtocol:  # pragma: no cover
                proto = None
            else:
                # Stop searching for working protocols.
                break

        # Protocol was found, and we connected to a server.
        if proto and connection.server:
            # Sets the connection protocol.
            connection.protocol = proto

            # Calls middleware for server initial connect.
            for middleware in self.middlewares:
                await middleware.server_connected(connection=connection)

            # Handles the data between the client and server.
            await proto.handle(connection=connection)

        # Protocol identified, but we did not connect to a server.
        elif proto and not connection.server:  # pragma: no cover
            raise ValueError(f"The protocol was found, but the server was not connected to succesfully. Check the {proto.__class__.__name__} implementation.")

        # No protocol was found for the data.
        else:  # pragma: no cover
            raise ValueError("No protocol was found. Check the protocols list.")

        # If a server connection exists after handling it, we close it.
        if connection.server and connection.server.mitm_managed:
            connection.server.writer.close()
            await connection.server.writer.wait_closed()

            # Calls the server's 'disconnected' middleware.
            for middleware in self.middlewares:
                await middleware.server_disconnected(connection=connection)

        # Attempts to disconnect with the client.
        # In some instances 'wait_closed()' might hang. This is a known issue that
        # happens when and if the client keeps the connection alive, and, unfortunately,
        # there is nothing we can do about it. This is a reported bug in asyncio.
        # https://bugs.python.org/issue39758
        if connection.client and connection.client.mitm_managed:
            connection.client.writer.close()
            await connection.client.writer.wait_closed()

            # Calls the client 'disconnected' middleware.
            for middleware in self.middlewares:
                await middleware.client_disconnected(connection=connection)

    def stop(self, result: Optional[Any] = None) -> Any:
        self._loop.call_soon_threadsafe(lambda: self._stop())

    def _stop(self):
        super().stop()
        self._clear_mid()
        for protocol in self.protocols:
            protocol.keep_alive = False
        self._loop.stop()

    def add_middleware(self, middleware: Middleware):
        # self._loop.call_soon_threadsafe(lambda: self.middlewares.append(middleware))
        # self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._add_mid(middleware)))
        # self._loop.call_soon_threadsafe(lambda: self._add_mid(middleware))
        if not self._loop:
            self._add_mid(middleware)
        else:
            self._loop.call_soon_threadsafe(lambda: self._add_mid(middleware))

    def _add_mid(self, middleware: Middleware):
        self.middlewares.append(middleware)
        for protocol in self.protocols:
            protocol.middlewares.append(middleware)
            # print("=======a",len(protocol.middlewares))
        # print("=======b",len(self.middlewares))

    def del_middleware(self, middleware: Middleware):
        # self._loop.call_soon_threadsafe(lambda: self.middlewares.append(middleware))
        # self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._add_mid(middleware)))
        # self._loop.call_soon_threadsafe(lambda: self._add_mid(middleware))
        if not self._loop:
            self._del_mid(middleware)
        else:
            self._loop.call_soon_threadsafe(lambda: self._del_mid(middleware))

    def _del_mid(self, middleware: Middleware):
        m = next((mid for mid in self.middlewares if mid.name == middleware.name), None)
        if m:
            self.middlewares.remove(m)
        for protocol in self.protocols:
            m = next((mid for mid in protocol.middlewares if mid.name == middleware.name), None)
            if m:
                protocol.middlewares.remove(m)

    def _clear_mid(self):
        self.middlewares.clear()
        for protocol in self.protocols:
            protocol.middlewares.clear()
