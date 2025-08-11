"""
Github: https://github.com/synchronizing/mitm
Docs: https://synchronizing.github.io/mitm/
"""

# pylint: disable=wrong-import-order, wrong-import-position

__project__ = "mitm"

import pathlib
import appdirs

__data__ = pathlib.Path(appdirs.user_data_dir(__package__))

import logging
import sys

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)

from mitm.core import *
from mitm.crypto import *
from mitm.extension import *
from mitm.mitm import *

__all__ = [
    "Host",
    "Connection",
    "Flow",
    "MITM",
    "Middleware",
    "Protocol",
    "InvalidProtocol",
    "CertificateAuthority",
]
