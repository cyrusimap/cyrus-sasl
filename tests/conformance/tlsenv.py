"""Channel binding data from real TLS sessions.

Runs a TLS handshake between two in-memory pyOpenSSL connections (no
sockets) with a throwaway certificate, and returns the channel binding
data each side derives, the way an application would before handing it
to libsasl with SASL_CHANNEL_BINDING:

  tls-exporter          RFC 9266: the TLS 1.3 exporter with label
                        "EXPORTER-Channel-Binding" and no context, 32 bytes
  tls-unique            RFC 5929: the first Finished message (TLS 1.2 only;
                        RFC 9266 says it MUST NOT be used with TLS 1.3)
  tls-server-end-point  RFC 5929: a hash of the server's certificate, here
                        SHA-256 because the certificate is signed with it

Call require() from a test's setUp(); it skips the test if pyOpenSSL or
cryptography is missing.
"""

import datetime
import hashlib
import unittest

CB_TYPES = ("tls-exporter", "tls-unique", "tls-server-end-point")

_cert = {}


def require():
    try:
        import OpenSSL.SSL  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("pyOpenSSL or cryptography not installed")


def _certificate():
    if not _cert:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        _cert["key"], _cert["cert"] = key, cert
    return _cert["key"], _cert["cert"]


def _handshake(version):
    from OpenSSL import SSL, crypto

    key, cert = _certificate()
    sctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    try:
        # pyOpenSSL 24.3 and later take cryptography objects directly.
        sctx.use_certificate(cert)
        sctx.use_privatekey(key)
    except TypeError:
        sctx.use_certificate(crypto.X509.from_cryptography(cert))
        sctx.use_privatekey(crypto.PKey.from_cryptography_key(key))
    cctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    for ctx in (sctx, cctx):
        ctx.set_min_proto_version(version)
        ctx.set_max_proto_version(version)
    server = SSL.Connection(sctx, None)
    server.set_accept_state()
    client = SSL.Connection(cctx, None)
    client.set_connect_state()

    done = {client: False, server: False}
    for _ in range(50):
        for conn in (client, server):
            if not done[conn]:
                try:
                    conn.do_handshake()
                    done[conn] = True
                except SSL.WantReadError:
                    pass
        for src, dst in ((client, server), (server, client)):
            try:
                data = src.bio_read(65536)
            except SSL.WantReadError:
                data = b""
            if data:
                dst.bio_write(data)
        if all(done.values()):
            return client, server
    raise RuntimeError("TLS handshake did not complete")


def _cert_der(getter):
    """DER of a connection's certificate, across pyOpenSSL versions."""
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        cert = getter(as_cryptography=True)
    except TypeError:
        cert = getter().to_cryptography()
    return cert.public_bytes(Encoding.DER)


def channel_bindings(cb_type):
    """Return (client_data, server_data) from a fresh TLS session."""
    from OpenSSL import SSL

    if cb_type == "tls-exporter":
        client, server = _handshake(SSL.TLS1_3_VERSION)
        label = b"EXPORTER-Channel-Binding"
        return (client.export_keying_material(label, 32),
                server.export_keying_material(label, 32))
    if cb_type == "tls-unique":
        client, server = _handshake(SSL.TLS1_2_VERSION)
        return client.get_finished(), server.get_peer_finished()
    if cb_type == "tls-server-end-point":
        client, server = _handshake(SSL.TLS1_3_VERSION)
        return (hashlib.sha256(_cert_der(client.get_peer_certificate)).digest(),
                hashlib.sha256(_cert_der(server.get_certificate)).digest())
    raise ValueError(cb_type)
