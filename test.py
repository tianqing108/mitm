import asyncio
import json
import logging
import queue
import threading
from http.cookies import SimpleCookie
from typing import Any, Optional

from mitm import MITM, protocol, crypto
from mitm.core import Connection, Middleware
from mitm.httpq import Response, Request

logger = logging.getLogger(__package__)
mitm: Optional[MITM] = None


class Intercept(Middleware):
    async def mitm_started(self, host: str, port: int):
        pass

    async def client_connected(self, connection: Connection):
        pass

    async def server_connected(self, connection: Connection):
        pass

    async def client_data(self, connection: Connection, data: bytes) -> bytes:
        return data

    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        return data

    async def client_disconnected(self, connection: Connection):
        pass

    async def server_disconnected(self, connection: Connection):
        pass


class TestIntercept(Intercept):
    name = "test"
    text_content_types = [
        "text/plain",
        "text/html",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded",
        "text/csv",
        "application/yaml",
        "text/yaml",
        "text/markdown",
        "application/x-sh",
        "text/x-shellscript",
    ]

    def __init__(self, que, params=None):
        super().__init__()
        self.connection: Connection = None
        self.params = params
        self.que = que

    async def client_data(self, connection: Connection, data: bytes) -> bytes:
        request = Request.parse(data)
        if b"OPTION" == request.method:
            return data
        if all(value is not None for value in self.params.values()):
            print("登录参数全部获取成功")
            self.que.put(self.params)
            mitm.del_middleware(self)
            return data

        if request.target and b"LoginCheckIn" in request.target and request.body:
            self.params["ServerUrl"] = request.headers[b"host"].decode()
        return data

    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        if b"GetAccountInfo" in connection.request.target:
            try:
                resp = Response.parse(data)
            except Exception:
                return data
            if not self.params["AccessToken"]:
                if b"x-jwtoken" in resp.headers:
                    AccessToken = resp.headers[b"x-jwtoken"].decode()
                    self.params["AccessToken"] = AccessToken
                elif b"authorization" in resp.headers:
                    AccessToken = resp.headers[b"authorization"].decode()
                    self.params["AccessToken"] = AccessToken

        return data


async def test(env: dict[str, Any]) -> dict[str, Any]:
    wait_queue = queue.Queue()
    params = dict.fromkeys(env)
    intercept = TestIntercept(wait_queue, params)
    while len(mitm.middlewares) > 0:
        logging.info("前面有登录正在执行")
        await asyncio.sleep(2)
    mitm.add_middleware(intercept)
    while True:
        try:
            params = await asyncio.to_thread(wait_queue.get, timeout=0.5)
            break
        except queue.Empty:
            pass
        except asyncio.TimeoutError:
            pass
    wait_queue.shutdown()
    return params


def start(proxy_port: int):
    """
    启动代理
    """
    global mitm
    mitm = MITM(host="127.0.0.1", port=proxy_port, protocols=[protocol.HTTP], middlewares=[], certificate_authority=crypto.CertificateAuthority())
    logger.debug("代理服务已开启")
    mitm.run()


def stop():
    """
    关闭代理
    """
    mitm.stop()
    logger.debug("代理服务已关闭")


if __name__ == "__main__":
    env = {
        "ServerUrl": None,
        "x-token": None,
    }
    t = threading.Thread(target=start, args=(9092,))
    t.start()
    t.join()
