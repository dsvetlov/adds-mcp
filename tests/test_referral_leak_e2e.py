"""End to end: no search can make the server hand its credentials to another host.

Two fake LDAP servers on 127.0.0.1. The "DC" speaks LDAPS and answers any base
it does not hold with a referral to the "recorder", a plain-LDAP server that
records every bind it receives. The real ReadOnlyADClient runs against them.
With ldap3's defaults the recorder receives the service account's DN and
password; it must receive nothing.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ldap3.protocol.rfc4511 import (
    LDAPDN,
    URI,
    AttributeDescription,
    AttributeValue,
    BindResponse,
    LDAPMessage,
    LDAPString,
    MessageID,
    PartialAttribute,
    PartialAttributeList,
    ProtocolOp,
    Referral,
    ResultCode,
    SearchResultDone,
    SearchResultEntry,
    Vals,
)
from ldap3.strategy.base import BaseStrategy
from pyasn1.codec.ber import decoder, encoder

from adds_mcp.client import ReadOnlyADClient, ReferralNotFollowed, SearchBaseOutOfScope
from adds_mcp.config import Settings

FOREST = "DC=example,DC=test"
CHILD = f"DC=child,{FOREST}"
PASSWORD = "S3cret-P@ss"

Handler = Callable[[int, object], bytes | None]


# ------------------------------------------------------------- LDAP messages


def _message(message_id: int, choice: str, operation: object) -> bytes:
    message = LDAPMessage()
    message["messageID"] = MessageID(message_id)
    protocol_op = ProtocolOp()
    protocol_op.setComponentByName(choice, operation)
    message["protocolOp"] = protocol_op
    return encoder.encode(message)


def _bind_ok(message_id: int) -> bytes:
    response = BindResponse()
    response["resultCode"] = ResultCode(0)
    response["matchedDN"] = LDAPDN("")
    response["diagnosticMessage"] = LDAPString("")
    return _message(message_id, "bindResponse", response)


def _search_done(message_id: int, code: int = 0, referral: str | None = None) -> bytes:
    done = SearchResultDone()
    done["resultCode"] = ResultCode(code)
    done["matchedDN"] = LDAPDN("")
    done["diagnosticMessage"] = LDAPString("")
    if referral:
        uris = Referral()
        uris.setComponentByPosition(0, URI(referral))
        done["referral"] = uris
    return _message(message_id, "searchResDone", done)


def _root_dse(message_id: int) -> bytes:
    entry = SearchResultEntry()
    entry["object"] = LDAPDN("")
    attributes = PartialAttributeList()
    for i, (name, values) in enumerate(
        {
            "namingContexts": [FOREST, f"CN=Configuration,{FOREST}"],
            "defaultNamingContext": [FOREST],
        }.items()
    ):
        attribute = PartialAttribute()
        attribute["type"] = AttributeDescription(name)
        vals = Vals()
        for j, value in enumerate(values):
            vals.setComponentByPosition(j, AttributeValue(value))
        attribute["vals"] = vals
        attributes.setComponentByPosition(i, attribute)
    entry["attributes"] = attributes
    return _message(message_id, "searchResEntry", entry) + _search_done(message_id)


# ------------------------------------------------------------------ servers


class _LdapServer:
    """A minimal threaded LDAP server: one handler call per request."""

    def __init__(self, handler: Handler, tls: ssl.SSLContext | None = None) -> None:
        self._handler = handler
        self._tls = tls
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            if self._tls is not None:
                conn = self._tls.wrap_socket(conn, server_side=True)
            buffer = b""
            while chunk := conn.recv(65536):
                buffer += chunk
                while (size := BaseStrategy.compute_ldap_message_size(buffer)) != -1 and len(
                    buffer
                ) >= size:
                    request, buffer = buffer[:size], buffer[size:]
                    message, _ = decoder.decode(request, asn1Spec=LDAPMessage())
                    reply = self._handler(int(message["messageID"]), message["protocolOp"])
                    if reply is None:
                        return
                    conn.sendall(reply)
        except OSError:
            return
        finally:
            conn.close()

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def tls_context(tmp_path: Path) -> ssl.SSLContext:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context


class _Directory:
    def __init__(self, tls_context: ssl.SSLContext) -> None:
        self.binds_received_elsewhere: list[tuple[str, str]] = []
        self.bases_seen_by_dc: list[str] = []
        self.recorder = _LdapServer(self._recorder)
        self.dc = _LdapServer(self._dc, tls=tls_context)
        self.client = ReadOnlyADClient(
            Settings(
                servers=["127.0.0.1"],
                port=self.dc.port,
                bind_dn=f"CN=svc,{FOREST}",
                bind_password=PASSWORD,
                base_dn=FOREST,
                tls_validate=False,  # self-signed test certificate
                query_timeout_seconds=5,
                _env_file=None,
            )
        )

    def _recorder(self, message_id: int, operation) -> bytes | None:
        name = operation.getName()
        if name == "bindRequest":
            bind = operation["bindRequest"]
            self.binds_received_elsewhere.append(
                (str(bind["name"]), bytes(bind["authentication"]["simple"]).decode())
            )
            return _bind_ok(message_id)
        if name == "searchRequest":
            return _search_done(message_id)
        return None

    def _dc(self, message_id: int, operation) -> bytes | None:
        name = operation.getName()
        if name == "bindRequest":
            return _bind_ok(message_id)
        if name != "searchRequest":
            return None
        base = str(operation["searchRequest"]["baseObject"])
        self.bases_seen_by_dc.append(base)
        if base == "":
            return _root_dse(message_id)
        lowered = base.lower()
        if lowered.endswith(FOREST.lower()) and not lowered.endswith(CHILD.lower()):
            return _search_done(message_id)
        # Not held here (another domain, or the child domain): refer elsewhere.
        return _search_done(message_id, 10, f"ldap://127.0.0.1:{self.recorder.port}/{base}")

    def close(self) -> None:
        self.client.close()
        self.dc.close()
        self.recorder.close()


@pytest.fixture
def directory(tls_context: ssl.SSLContext) -> Iterator[_Directory]:
    fake = _Directory(tls_context)
    yield fake
    fake.close()


def _search(directory: _Directory, base: str) -> RuntimeError | None:
    """Run a search; return the error it raised, if any."""
    try:
        directory.client.search(search_filter="(objectClass=*)", base_dn=base)
    except RuntimeError as exc:
        return exc
    return None


def test_a_foreign_base_is_refused_and_never_reaches_the_dc(directory: _Directory) -> None:
    outcome = _search(directory, "DC=evil,DC=example")
    assert directory.binds_received_elsewhere == []  # the credentials never left
    assert "DC=evil,DC=example" not in directory.bases_seen_by_dc
    assert isinstance(outcome, SearchBaseOutOfScope)


def test_a_referral_from_the_dc_is_reported_and_never_followed(directory: _Directory) -> None:
    # The child domain lies under the configured base, so the scope check lets it
    # through; the DC refers it elsewhere and only the referral settings stand
    # between the credentials and the other host.
    outcome = _search(directory, f"OU=Staff,{CHILD}")
    assert directory.binds_received_elsewhere == []  # the credentials never left
    assert f"OU=Staff,{CHILD}" in directory.bases_seen_by_dc
    assert isinstance(outcome, ReferralNotFollowed)  # not an empty "nothing found"


def test_a_base_inside_the_directory_is_answered_normally(directory: _Directory) -> None:
    assert _search(directory, f"OU=Staff,{FOREST}") is None
    assert directory.binds_received_elsewhere == []
