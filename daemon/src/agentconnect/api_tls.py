"""TLS for the local API on loopback TCP, with a pinned certificate (SR-08).

On TCP any local user can bind the port while the daemon is down, so the
clients authenticate the daemon before sending anything. The daemon keeps a
self-signed certificate and its key in the data directory, with the
certificate's SHA-256 next to the API tokens:

* ``api-tls.crt``: the certificate (ECDSA P-256, ``127.0.0.1`` and
  ``localhost``), PEM. ``curl --cacert`` takes it.
* ``api-tls.key``: its private key, PKCS#8 PEM.
* ``api-tls.sha256``: the certificate's SHA-256 (of the DER), in hex.

All three are 0600 and owned by the daemon's user; a looser one stops the
start, as a loose token file does. The certificate is valid for
:data:`LIFETIME` and replaced :data:`RENEW_BEFORE` its expiry, when the
daemon starts and while it runs; it is also replaced when a file is missing
or damaged, or when the key, certificate and fingerprint don't belong
together. Deleting the three files and restarting rotates it on demand.

Clients read the certificate and fingerprint from the directory they read
the token from, on every connection, so a rotation needs no new client.
They trust only that certificate (chain, ``127.0.0.1`` and dates checked by
OpenSSL) and compare the presented certificate's SHA-256 with the
fingerprint before writing a byte (:mod:`agentconnect.sockets`).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import ssl
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agentconnect import log
from agentconnect.keystore import write_private

LOG = log.get("agentconnect.api_tls")

CERT_FILE = "api-tls.crt"
KEY_FILE = "api-tls.key"
FINGERPRINT_FILE = "api-tls.sha256"
LIFETIME = timedelta(days=90)
RENEW_BEFORE = timedelta(days=30)
# Valid from a little before it was made, for clocks slightly behind.
BACKDATE = timedelta(hours=1)
HOST = "127.0.0.1"


@dataclass(frozen=True)
class ServerCert:
    """The daemon's certificate on disk."""

    cert: Path
    key: Path
    fingerprint: str  # hex SHA-256 of the DER certificate
    not_after: datetime

    @property
    def renew_at(self) -> datetime:
        return self.not_after - RENEW_BEFORE


def _check_private(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.geteuid():
        msg = f"{path.name} must be a file owned by this user with mode 0600"
        raise PermissionError(msg)


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _load(data_dir: Path) -> tuple[ServerCert | None, str]:
    """The certificate on disk if its three files are present and belong
    together; else ``None`` and why not."""
    paths = [data_dir / n for n in (CERT_FILE, KEY_FILE, FINGERPRINT_FILE)]
    present = [p for p in paths if p.exists() or p.is_symlink()]
    for p in present:
        _check_private(p)
    if len(present) < len(paths):
        return None, "missing" if not present else "incomplete"
    cert_file, key_file, fp_file = paths
    try:
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        key = load_pem_private_key(key_file.read_bytes(), password=None)
        pinned = fp_file.read_text(encoding="ascii").strip()
    except (ValueError, TypeError, UnicodeDecodeError):
        return None, "unreadable"
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.public_key() != cert.public_key():
        return None, "key_mismatch"
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return None, "unreadable"
    found = fingerprint(cert.public_bytes(Encoding.DER))
    if not hmac.compare_digest(found, pinned):
        return None, "fingerprint_mismatch"
    return ServerCert(cert_file, key_file, found, cert.not_valid_after_utc), ""


def _create(data_dir: Path, now: datetime) -> ServerCert:
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agentconnectd")])
    not_after = now + LIFETIME
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(HOST)), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    # The key first and the fingerprint last: a client that reads in
    # between sees a certificate that doesn't match the old fingerprint and
    # refuses that one connection; it never trusts a mismatched pair.
    write_private(
        data_dir / KEY_FILE, key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    write_private(data_dir / CERT_FILE, cert.public_bytes(Encoding.PEM))
    write_private(data_dir / FINGERPRINT_FILE, f"{fingerprint(der)}\n".encode("ascii"))
    return ServerCert(
        data_dir / CERT_FILE, data_dir / KEY_FILE, fingerprint(der), cert.not_valid_after_utc
    )


def ensure_certificate(data_dir: Path, now: datetime) -> ServerCert:
    """The daemon's certificate, created or replaced when it is missing,
    damaged, mismatched, or due for renewal at ``now``. Raises
    ``PermissionError`` for a file that isn't private."""
    current, why = _load(data_dir)
    if current is not None and now < current.renew_at:
        return current
    if current is not None:
        why = "expired" if now >= current.not_after else "renewal"
    made = _create(data_dir, now)
    LOG.info("api_tls_certificate", reason=why, not_after=made.not_after.isoformat())
    return made


def server_context(cert: ServerCert) -> ssl.SSLContext:
    """The TCP listener's TLS context: TLS 1.2 or later, this certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert.cert, cert.key)
    return ctx


# -- the client side ------------------------------------------------------------


class PinError(Exception):
    """The presented certificate isn't the pinned one."""


@dataclass(frozen=True)
class Pin:
    """What a client trusts: the context and the expected SHA-256."""

    context: ssl.SSLContext
    digest: bytes


def read_pin(token_dir: Path) -> Pin:
    """The certificate and fingerprint in ``token_dir``, as a client context
    that trusts only that certificate. Raises ``FileNotFoundError`` when
    there is none, :class:`PinError` when the two don't match."""
    pem = (token_dir / CERT_FILE).read_text(encoding="ascii")
    pinned = (token_dir / FINGERPRINT_FILE).read_text(encoding="ascii").strip()
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        msg = f"{token_dir / CERT_FILE} is not a certificate"
        raise PinError(msg) from None
    if not hmac.compare_digest(fingerprint(der), pinned):
        msg = f"the certificate and {FINGERPRINT_FILE} in {token_dir} don't match"
        raise PinError(msg)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # hostname and chain checked
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cadata=der)
    return Pin(ctx, bytes.fromhex(pinned))


def check_peer(ssl_object: Any, pin: Pin) -> None:
    """Raise :class:`PinError` unless the connection's certificate is the
    pinned one."""
    der = ssl_object.getpeercert(True)
    if der is None or not hmac.compare_digest(hashlib.sha256(der).digest(), pin.digest):
        msg = "the server's certificate is not the pinned one"
        raise PinError(msg)
