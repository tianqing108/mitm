"""
`httpq` implementation.
"""

from __future__ import annotations

import enum
import gzip
import zlib
import brotli
from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

import zstandard


def decode_chunked_data(chunked_data):
    data = b""
    while True:
        # 查找第一个 \r\n，表示块长度结束
        chunk_size_end = chunked_data.find(b"\r\n")
        if chunk_size_end == -1:
            break  # 没有找到块长度，结束循环

        # 获取块长度（十六进制）
        chunk_size_hex = chunked_data[:chunk_size_end]
        chunk_size = int(chunk_size_hex, 16)  # 将十六进制转换为整数

        if chunk_size == 0:
            break  # 块长度为0，表示分块结束

        # 获取块数据
        chunk_start = chunk_size_end + 2  # 跳过 \r\n
        chunk_end = chunk_start + chunk_size
        chunk = chunked_data[chunk_start:chunk_end]

        # 将块数据添加到结果中
        data += chunk

        # 移动到下一个块
        chunked_data = chunked_data[chunk_end + 2:]  # 跳过 \r\n

    return data


def decode_content_body(data: bytes, encoding: str=None) -> bytes:
    if not encoding:
        if data.startswith(b"\x1f\x8b"):
            encoding = "gzip"
        elif data.startswith(b"\x28\xb5\x2f\xfd"):
            encoding = "zstd"
        elif data.startswith(b"\x78"):
            encoding = "deflate"
        elif data.startswith(b"\xce\x2f\xb5"):
            encoding = "br"
        else:
            encoding = "identity"

    if encoding == "identity":
        text = data
    elif encoding in ("gzip", "x-gzip"):
        text = gzip.decompress(data)
    elif encoding == "deflate":
        try:
            text = zlib.decompress(data)
        except zlib.error:
            text = zlib.decompress(data, -zlib.MAX_WBITS)
    elif encoding == "br":
        text = brotli.decompress(data)
    elif encoding == "zstd":
        try:
            text = zstandard.decompress(data)
        except zstandard.ZstdError:
            text = zstandard.decompress(data, 10 * 1024 * 1024)
    else:
        raise Exception("Unknown Content-Encoding: %s" % encoding)
    return text

class State(enum.Enum):
    """
    States of the HTTP request.
    """

    TOP = 0
    HEADER = 1
    BODY = 2


class Headers(Dict[bytes,Tuple]):

    """
    Container for HTTP headers.
    """

    def __init__(self, value: bytes):
        super().__init__()


    def _compile(self) -> bytes:
        """
        Compile the headers.
        """
        lines = []
        for k, v in self.items():
            if isinstance(v, list):
                string = b"%s: " % k + b", ".join([i for i in self[k]]) + b"\r\n"
            else:
                string = b"%s: %s\r\n" % (k, v)

            lines.append(string)

        return b"%s\r\n" % b"".join(lines)

    def __setitem__(self, key: Any, value: Any):
        """
        Deletes the previous value of the item and sets the new value.

        Args:
            key: The key of the item.
            value: The value of the item.
        """
        if key in self:
            del self[key]

        super().__setitem__(key, value)

    def __defaultsetitem__(self, key: Any, value: Any):
        """
        Sets the value of the item without deleting the previous value.

        Args:
            key: The key of the item.
            value: The value of the item.
        """
        super().__setitem__(key, value)

    @property
    def raw(self) -> bytes:
        """
        The raw headers.
        """
        return self._compile()




class Message(ABC):
    __slots__ = ("protocol", "headers", "body", "buffer")

    def __init__(
            self,
            protocol: bytes = None,
            headers: Headers = {},
            body: bytes = None,
    ):
        """
        Initializes an HTTP message.

        Args:
            protocol: The protocol of the HTTP message.
            headers: The headers of the HTTP message.
            body: The body of the HTTP message.

        Note:
            :py:class:`Message` is the base class for :py:class:`Request` and
            :py:class:`Response`, and is not intended to be used directly.
        """
        self.protocol = protocol
        self.headers = headers
        self.body = body
        self.buffer = b""

    def __setattr__(self, name: str, value: Any):
        """
        Sets the value of the attribute. Defaults to ``toolbox.collections.Item``.

        Args:
            name: The name of the attribute.
            value: The value of the attribute.
        """
        if name == "headers":
            super().__setattr__(name, Headers(value))
        elif name == "buffer":
            super().__setattr__(name, value)
        else:
            super().__setattr__(name, value)

    def feed(self, msg: bytes) -> State:
        """
        Adds chuncks of the message to the internal buffer.

        Args:
            msg: The message to add to the internal buffer.
        """

        # Checks the msg type:
        if not isinstance(msg, bytes):
            raise TypeError("Message must be bytes.")

        self.buffer += msg
        return self.state

    @property
    def state(self) -> State:
        if self.buffer.count(b"\r\n") > 0 and b"\r\n\r\n" not in self.buffer:
            return State.HEADER
        elif self.buffer.count(b"\r\n") == 0:
            return State.TOP

        current = State.TOP
        _, body = self.buffer.split(b"\r\n\r\n", 1)

        # Split the message into lines.
        for line in self.buffer.split(b"\r\n"):
            # Parses the first line of the HTTP/1.1 msg.
            if current == State.TOP:
                self._parse_top(line)
                current = State.HEADER

            # Parse the headers of the HTTP/1.1 msg.
            elif current == State.HEADER:
                if b":" in line:
                    key, value = line.split(b":", 1)
                    key = key.lower()
                    if b"," in value:
                        value = value.split(b",")
                    else:
                        value = [value]

                    for v in value:
                        if key not in self.headers or v.strip() not in self.headers[key]:
                            self.headers.__defaultsetitem__(key, v.strip())
                else:
                    current = State.BODY

        if current == State.BODY:
            self.body = body

        return current

    @abstractmethod
    def _parse_top(self, line: bytes):  # pragma: no cover
        """
        Parses the first line of the HTTP message.
        """
        raise NotImplementedError

    @classmethod
    def parse(cls, msg: bytes) -> "Message":
        """
        Parses a complete HTTP message.

        Args:
            msg: The message to parse.
        """
        obj = cls()
        obj.feed(msg)
        return obj

    @abstractmethod
    def _compile_top(self) -> bytes:  # pragma: no cover
        """
        Compiles the first line of the HTTP message.
        """
        raise NotImplementedError

    def _compile(self) -> bytes:
        """
        Compiles a complete HTTP message.
        """
        return b"%s%s%s" % (self._compile_top(), self.headers.raw, self.body)

    @property
    def raw(self) -> bytes:
        """
        Returns the raw (bytes) HTTP message.
        """
        return self._compile()

    def __eq__(self, other: Message) -> bool:
        """
        Compares two HTTP messages.
        """
        return self.raw == other.raw

    def __str__(self) -> str:
        """
        Pretty-print of the HTTP message.
        """

        if self.__class__ == Request:
            arrow = "→ "
        elif self.__class__ == Response:
            arrow = "← "
        else:  # pragma: no cover
            arrow = "? "

        return arrow + arrow.join(self._compile().decode().rstrip("\r\n").splitlines(True))


class Request(Message):
    __slots__ = Message.__slots__ + ("method", "target")

    def __init__(
            self,
            method: bytes = None,
            target: bytes = None,
            protocol: bytes = None,
            headers: Headers = {},
            body: bytes = None,
    ):
        """
        Initializes an HTTP request.

        Args:
            method: The method of the HTTP request.
            target: The target of the HTTP request.
            protocol: The protocol of the HTTP request.
            headers: The headers of the HTTP request.
            body: The body of the HTTP request.
        """
        super().__init__(protocol, headers, body)
        self.method = method
        self.target = target

        objs = [self.method, self.target, self.protocol]
        if all(obj is None for obj in objs):
            self.buffer = b""
        elif all(obj for obj in objs):
            self.buffer = b"%s %s %s\r\n" % (
                self.method,
                self.target,
                self.protocol,
            )
        else:
            raise ValueError("Request must have method, target, and protocol.")

        if self.headers:
            self.buffer += self.headers.raw + b"\r\n\r\n"

        if self.body:
            self.buffer += self.body

    def _parse_top(self, line: bytes):
        """
        Parses the first line of the HTTP request.
        """
        self.method, self.target, self.protocol = line.split(b" ")

    def _compile_top(self):
        """
        Compiles the first line of the HTTP request.
        """
        return b"%s %s %s\r\n" % (self.method, self.target, self.protocol)


class Response(Message):
    __slots__ = Message.__slots__ + ("status", "reason")

    def __init__(
            self,
            protocol: bytes = None,
            status: bytes = None,
            reason: bytes = None,
            headers: Headers = {},
            body: bytes = None,
    ):
        """
        Initializes an HTTP response.

        Args:
            protocol: The protocol of the HTTP response.
            status: The status of the HTTP response.
            reason: The reason of the HTTP response.
            headers: The headers of the HTTP response.
            body: The body of the HTTP response.
        """
        super().__init__(protocol, headers, body)
        self.status = status
        self.reason = reason

        objs = [self.protocol, self.status, self.reason]
        if all(obj is None for obj in objs):
            self.buffer = b""
        elif all(obj for obj in objs):
            self.buffer = b"%s %s %s\r\n" % (
                self.protocol,
                self.status,
                self.reason,
            )
        else:
            raise ValueError("Response must have protocol, status, and reason.")

        if self.headers:
            self.buffer += self.headers.raw + b"\r\n\r\n"

        if self.body:
            self.buffer += self.body
    @property
    def decode_body(self):
        return decode_content_body(decode_chunked_data(self.body))

    def _parse_top(self, line: bytes):
        """
        Parses the first line of the HTTP response.
        """
        try:
            self.protocol, self.status, self.reason = line.split(b" ", maxsplit=2)
        except:  # noqa: E722
            pass

    def _compile_top(self) -> bytes:
        """
        Parses the first line of the HTTP response.
        """
        return b"%s %s %s\r\n" % (self.protocol, self.status, self.reason)