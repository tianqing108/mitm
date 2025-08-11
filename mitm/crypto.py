"""
Cryptography functionalities.
"""
import ipaddress
from functools import lru_cache
import ssl
from pathlib import Path
from typing import Optional, Tuple, Union
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from mitm import __data__

LRU_MAX_SIZE = 1024

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def new_RSA(bits: int = 2048) -> rsa.RSAPrivateKey:
    """Generate RSA private key using cryptography"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )

def new_X509(
    country_name: str = "US",
    state_or_province_name: str = "New York",
    locality: str = "New York",
    organization_name: str = "mitm",
    organization_unit_name: str = "mitm",
    common_name: str = "mitm",
    serial_number: Optional[int] = None,
    time_not_before: Optional[datetime] = None,
    time_not_after: Optional[datetime] = None,
) -> x509.CertificateBuilder:
    """Generate X509 certificate using cryptography"""
    if time_not_before is None:
        time_not_before = datetime.utcnow()
    if time_not_after is None:
        time_not_after = time_not_before + timedelta(days=365)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    builder = builder.not_valid_before(time_not_before)
    builder = builder.not_valid_after(time_not_after)
    builder = builder.serial_number(serial_number or x509.random_serial_number())
    # builder = builder.public_key(None)  # To be set later
    return builder

class CertificateAuthority:
    def __init__(
        self,
        key: Optional[rsa.RSAPrivateKey] = None,
        cert: Optional[x509.Certificate] = None,
    ):
        self.key = key or new_RSA()
        builder = new_X509(common_name="mitm CA")
        builder = builder.public_key(self.key.public_key())

        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
            critical=False,
        )

        # Self-sign
        self.cert = builder.sign(
            private_key=self.key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

    @classmethod
    def init(cls, path: Path):
        pem, key = path / "mitm.pem", path / "mitm.key"
        if not pem.exists() or not key.exists():
            ca = CertificateAuthority()
            ca.save(pem, key)
        else:
            ca = CertificateAuthority.load(pem, key)
        return ca

    def new_X509(self, host: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        key = new_RSA()
        builder = new_X509(common_name=host)
        builder = builder.public_key(key.public_key())

        # Add SAN extensions
        san_list = []
        if is_ip(host):
            san_list.append(x509.IPAddress(ipaddress.ip_address(host)))
        else:
            san_list.append(x509.DNSName(host))
            san_list.append(x509.DNSName(f"*.{host}"))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

        # Sign with CA
        cert = builder.sign(
            private_key=self.key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        return cert, key

    @lru_cache(maxsize=LRU_MAX_SIZE)
    def new_context(self, host: str) -> ssl.SSLContext:
        cert, key = self.new_X509(host)

        # Write to temporary files
        cert_path = __data__ / "temp.crt"
        key_path = __data__ / "temp.key"

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        cert_path.unlink()
        key_path.unlink()

        return context

    def save(self, cert_path: Union[Path, str], key_path: Union[Path, str]):
        cert_path = Path(cert_path)
        key_path = Path(key_path)

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        with cert_path.open("wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))

        key_path.parent.mkdir(parents=True, exist_ok=True)
        with key_path.open("wb") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    @classmethod
    def load(cls, cert_path: Union[Path, str], key_path: Union[Path, str]) -> "CertificateAuthority":
        cert_path = Path(cert_path)
        key_path = Path(key_path)

        with cert_path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with key_path.open("rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        return cls(key, cert)