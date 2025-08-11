"""
Custom middlware implementation for the MITM proxy.
"""

import logging

from ..color import bold

from mitm import httpq
from mitm.core import Connection, Middleware

logger = logging.getLogger(__package__)


class Log(Middleware):
    """
    Middleware that logs all events to the console.
    """

    def __init__(self):
        self.connection: Connection = None

    async def mitm_started(self, host: str, port: int):
        logger.info(f"MITM server started on {bold(f'{host}:{port}')}.")

    async def client_connected(self, connection: Connection):
        logger.info(f"Client {bold(connection.client)} has connected.")

    async def server_connected(self, connection: Connection):
        logger.info(f"Client {bold(connection.client)} has connected to server {bold(connection.server)}.")

    async def client_data(self, connection: Connection, data: bytes) -> bytes:

        # The first request is intended for the 'mitm' server to discover the
        # destination server.
        if not connection.server:
            logger.info(f"Client {connection.client} to mitm: \n\n\t{data}\n")

        # All requests thereafter are intended for the destination server.
        else:  # pragma: no cover
            logger.info(f"Client {connection.client} to {connection.server}: \n\n\t{data}\n")

        return data

    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        logger.info(f"Server {connection.server} to client {connection.client}: \n\n\t{data}\n")
        return data

    async def client_disconnected(self, connection: Connection):
        logger.info(f"Client {connection.client} has disconnected.")

    async def server_disconnected(self, connection: Connection):
        logger.info(f"Server {connection.server} has disconnected.")


class HTTPLog(Log):  # pragma: no cover
    """
    Middlewares that logs all HTTP events to the console with pretty-print.

    Notes:
        Do not use this middleware if there is a chance that the request or response
        will not be HTTP. This should only be used if you have control of all the
        requests coming into the proxy. If you are setting your computer's proxy
        settings to `mitm` you should not use this middleware as things will not work.
    """

    def __init__(self):  # pylint: disable=super-init-not-called
        self.connection: Connection = None

    async def client_data(self, connection: Connection, data: bytes) -> bytes:

        req = httpq.Request.parse(data)

        # The first request is intended for the 'mitm' server to discover the
        # destination server.
        if not connection.server:
            logger.info(f"Client {connection.client} to mitm: \n\n{req}\n")

        # All requests thereafter are intended for the destination server.
        else:
            logger.info(f"Client {connection.client} to {connection.server}: \n\n{req}\n")

        return data

    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        resp = httpq.Response.parse(data)
        logger.info(f"Server {connection.server} to client {connection.client}: \n\n{resp}\n")
        return data

    async def client_disconnected(self, connection: Connection):
        logger.info(f"Client {connection.client} has disconnected.")

    async def server_disconnected(self, connection: Connection):
        logger.info(f"Server {connection.server} has disconnected.")
