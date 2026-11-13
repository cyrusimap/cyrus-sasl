"""GSSAPI (RFC 4752) wire-level conformance tests.

The Python side uses the gssapi module against a throwaway KDC
(krb5env.py), so it holds a real GSS-API context: it builds and checks the
final security-layer negotiation itself, and can wrap, replay and inspect
security-layer packets.

Security layer bit-masks (RFC 4752 section 3.3): 1 none, 2 integrity,
4 confidentiality.  Each security-layer packet is a 4-octet big-endian
length followed by a GSS_Wrap token.
"""

import unittest

try:
    import gssapi
    import gssapi.raw
except ImportError:
    raise unittest.SkipTest("Python gssapi module not installed")

import krb5env
from sasltest import SaslTestCase, config_defined, known_bug, spec

LAYER_NONE, LAYER_INTEGRITY, LAYER_CONF = 1, 2, 4
F = gssapi.RequirementFlag
CLIENT_FLAGS = [F.mutual_authentication, F.out_of_sequence_detection,
                F.replay_detection, F.integrity, F.confidentiality]
SPNEGO = gssapi.raw.OID.from_int_seq("1.3.6.1.5.5.2")
TARGET = "%s@%s" % (krb5env.SERVICE, krb5env.HOST)


def frame(token):
    return len(token).to_bytes(4, "big") + token


def unframe(packet):
    length = int.from_bytes(packet[:4], "big")
    assert len(packet) == 4 + length, "bad security-layer framing"
    return packet[4:]


def negotiation(layer, maxbuf, authzid=b""):
    return bytes([layer]) + maxbuf.to_bytes(3, "big") + authzid


class GssClientPeer:
    """Plays the RFC 4752 client against the library's server."""

    def __init__(self, server, flags=CLIENT_FLAGS, mech=gssapi.MechType.kerberos):
        self.server = server
        self.ctx = gssapi.SecurityContext(
            name=gssapi.Name(TARGET, gssapi.NameType.hostbased_service),
            usage="initiate", mech=mech, flags=flags)

    def authenticate(self):
        """Run context establishment; return the server's 4-octet offer.

        Returns (layers, maxbuf, conf_state) from the server's wrapped
        message, or the failing Result if the server stopped early.
        """
        r = self.server.start(self.ctx.step())
        while r.cont and not self.ctx.complete:
            token = self.ctx.step(r.out)
            r = self.server.step(token or b"")
        if not r.cont:
            return r
        if r.out == b"":
            # The server sent its last context token; we reply with no data.
            r = self.server.step(b"")
            if not r.cont:
                return r
        unwrapped = self.ctx.unwrap(r.out)
        self.offer = unwrapped.message
        return unwrapped

    def choose(self, layer, maxbuf=0x10000, authzid=b"", encrypt=False):
        """Send the client's wrapped choice; return the server's Result."""
        wrapped = self.ctx.wrap(negotiation(layer, maxbuf, authzid), encrypt)
        return self.server.step(wrapped.message)


class GssapiServer(SaslTestCase):

    def setUp(self):
        super().setUp()
        krb5env.require()

    def gss_server(self, **kw):
        kw.setdefault("success_data", True)
        s = self.server("GSSAPI", **kw)
        if "GSSAPI" not in s.mechs:
            self.skipTest("GSSAPI not available")
        return s

    def established(self, layer, **kw):
        """A server and peer that completed authentication with `layer`."""
        peer = GssClientPeer(self.gss_server(**kw))
        peer.authenticate()
        # RFC 4752 section 3.1: the maximum buffer MUST be 0 with no layer.
        r = peer.choose(layer, maxbuf=0 if layer == LAYER_NONE else 0x10000)
        self.assertOk(r)
        return peer, r

    # --- authentication ---

    @spec("RFC 4752", "3.2", "MUST", "server authenticates a Kerberos V5 client")
    def test_valid_exchange(self):
        peer, r = self.established(LAYER_NONE)
        self.assertEqual(r.user, b"user")
        self.assertEqual(r.ssf, 0)

    @spec("RFC 4752", "3.2", "MUST",
          "server wraps 4 octets: layer bit-mask and maximum buffer size")
    def test_server_offer(self):
        peer = GssClientPeer(self.gss_server())
        offer = peer.authenticate()
        self.assertEqual(len(offer.message), 4)
        layers = offer.message[0]
        self.assertTrue(layers & (LAYER_INTEGRITY | LAYER_CONF))
        self.assertGreater(int.from_bytes(offer.message[1:4], "big"), 0)

    @spec("RFC 4752", "3.2", "MUST", "server wraps its offer with conf_flag FALSE")
    def test_server_offer_not_encrypted(self):
        peer = GssClientPeer(self.gss_server())
        self.assertFalse(peer.authenticate().encrypted)

    @spec("RFC 4752", "3.2", "MUST",
          "maximum buffer MUST be 0 if the server supports no security layer")
    def test_offer_without_layers(self):
        peer = GssClientPeer(self.gss_server(max_ssf=0))
        offer = peer.authenticate()
        self.assertEqual(offer.message[0], LAYER_NONE)
        self.assertEqual(offer.message[1:4], b"\0\0\0")

    @known_bug("S5", "server accepts any GSS mechanism under the name GSSAPI")
    @spec("RFC 4752", "3.2", "MUST",
          "if the negotiated mechanism isn't Kerberos V5, authentication MUST be aborted")
    def test_spnego_token_rejected(self):
        peer = GssClientPeer(self.gss_server(), mech=SPNEGO)
        r = peer.authenticate()
        if not getattr(r, "failed", False):
            r = peer.choose(LAYER_NONE, maxbuf=0)
        self.assertFailed(r)

    # --- the client's choice ---

    @spec("RFC 4752", "3.2", "REQUIRED",
          "server verifies the client selected a security layer that was offered")
    def test_layer_not_offered(self):
        peer = GssClientPeer(self.gss_server(max_ssf=0))
        peer.authenticate()
        self.assertFailed(peer.choose(LAYER_INTEGRITY))

    @spec("RFC 4752", "3.2", "REQUIRED",
          "server verifies the client maximum buffer is 0 if no layer was chosen")
    def test_no_layer_with_nonzero_maxbuf(self):
        peer = GssClientPeer(self.gss_server())
        peer.authenticate()
        self.assertFailed(peer.choose(LAYER_NONE, maxbuf=0x10000))

    @spec("RFC 4752", "3.2", "MUST", "server verifies src_name may act as the authzid")
    def test_authzid_not_permitted(self):
        peer = GssClientPeer(self.gss_server())
        peer.authenticate()
        self.assertFailed(peer.choose(LAYER_NONE, maxbuf=0, authzid=b"admin"))

    @spec("RFC 4752", "3.2", "MUST", "an authorized authzid is honored")
    def test_authzid_permitted(self):
        peer = GssClientPeer(self.gss_server(proxies=[("user", "admin")]))
        peer.authenticate()
        r = peer.choose(LAYER_NONE, maxbuf=0, authzid=b"admin")
        self.assertOk(r)
        self.assertEqual(r.user, b"admin")
        self.assertEqual(r.authuser, b"user")

    # --- the security layer ---

    @spec("RFC 4752", "3.3", "MUST", "integrity layer: data round-trips both ways")
    def test_integrity_layer(self):
        peer, r = self.established(LAYER_INTEGRITY)
        self.assertEqual(r.ssf, 1)
        d = peer.server.decode(frame(peer.ctx.wrap(b"from client", False).message))
        self.assertOk(d)
        self.assertEqual(d.out, b"from client")
        e = peer.server.encode(b"from server")
        self.assertOk(e)
        unwrapped = peer.ctx.unwrap(unframe(e.out))
        self.assertEqual(unwrapped.message, b"from server")
        self.assertFalse(unwrapped.encrypted)

    @spec("RFC 4752", "3.3", "MUST",
          "confidentiality layer: the sender wraps with conf_flag TRUE")
    def test_confidentiality_layer(self):
        peer, r = self.established(LAYER_CONF)
        self.assertGreater(r.ssf, 1)
        e = peer.server.encode(b"secret")
        self.assertOk(e)
        unwrapped = peer.ctx.unwrap(unframe(e.out))
        self.assertEqual(unwrapped.message, b"secret")
        self.assertTrue(unwrapped.encrypted)

    @known_bug("S3", "GSS_Unwrap supplementary status (replay) is ignored")
    @spec("RFC 4752", "3.3", "MUST",
          "GSS_Unwrap status other than GSS_S_COMPLETE MUST be a fatal error")
    def test_replayed_packet_rejected(self):
        peer, r = self.established(LAYER_INTEGRITY)
        packet = frame(peer.ctx.wrap(b"pay $100", False).message)
        self.assertOk(peer.server.decode(packet))
        self.assertFailed(peer.server.decode(packet), "replayed packet was accepted")

    @known_bug("S3", "decode doesn't check that the packet was encrypted")
    @spec("RFC 4752", "3.3", "MUST",
          "with confidentiality negotiated, data MUST be wrapped with conf_flag TRUE")
    def test_unencrypted_packet_rejected(self):
        peer, r = self.established(LAYER_CONF)
        packet = frame(peer.ctx.wrap(b"in the clear", False).message)
        self.assertFailed(peer.server.decode(packet),
                          "integrity-only packet accepted on a confidential layer")

    @known_bug("S4", "both layer bits select integrity instead of confidentiality")
    @spec("RFC 4752", "3.3", "MUST",
          "a client asking for confidentiality must get conf_flag TRUE data")
    def test_both_layer_bits(self):
        # Cyrus clients send 6 with GSSAPI's ad_compat option; the server's
        # own code means to treat it as confidentiality.
        peer = GssClientPeer(self.gss_server())
        peer.authenticate()
        r = peer.choose(LAYER_INTEGRITY | LAYER_CONF)
        self.assertOk(r)
        e = peer.server.encode(b"secret")
        self.assertTrue(peer.ctx.unwrap(unframe(e.out)).encrypted,
                        "server sent unencrypted data (SSF %s)" % r.ssf)


class GssServerPeer:
    """Plays the RFC 4752 server against the library's client."""

    def __init__(self, client):
        self.client = client
        self.ctx = gssapi.SecurityContext(
            usage="accept", creds=gssapi.Credentials(usage="accept"))

    def establish(self):
        """Accept the client's context; return the Result after our last token."""
        r = self.client.first
        while not self.ctx.complete:
            token = self.ctx.step(r.out)
            r = self.client.step(token or b"")
            if r.failed:
                return r
        return r

    def offer(self, layers, maxbuf=0x10000, raw=None):
        message = raw if raw is not None else bytes([layers]) + maxbuf.to_bytes(3, "big")
        return self.client.step(self.ctx.wrap(message, False).message)


class GssapiClient(SaslTestCase):

    def setUp(self):
        super().setUp()
        krb5env.require()

    def gss_client(self, **kw):
        c = self.client("GSSAPI", **kw)
        if c.first.name == "SASL_NOMECH":
            self.skipTest("GSSAPI not available")
        self.assertContinue(c.first)
        return c

    @spec("RFC 4752", "3.1", "MUST",
          "client requests integrity, and mutual and sequence for a security layer")
    def test_requested_flags(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        flags = peer.ctx.actual_flags
        for flag in (F.integrity, F.mutual_authentication, F.out_of_sequence_detection):
            self.assertIn(flag, flags)

    @spec("RFC 4752", "3.1", "MUST", "client completes with an offered layer")
    def test_valid_exchange(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        r = peer.offer(LAYER_NONE | LAYER_INTEGRITY | LAYER_CONF)
        self.assertOk(r)
        choice = peer.ctx.unwrap(r.out)
        self.assertFalse(choice.encrypted, "client wrapped its choice with conf_flag TRUE")
        self.assertGreaterEqual(len(choice.message), 4)
        self.assertIn(choice.message[0], (LAYER_NONE, LAYER_INTEGRITY, LAYER_CONF))

    @spec("RFC 4752", "3.1", "MUST", "client selects only a layer the server offered")
    def test_only_offered_layer(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        r = peer.offer(LAYER_INTEGRITY)
        if r.ok:
            self.assertEqual(peer.ctx.unwrap(r.out).message[0], LAYER_INTEGRITY)
        else:
            self.assertFailed(r)

    @spec("RFC 4752", "3.1", "MUST",
          "client fails if the server's cleartext is not 4 octets")
    def test_offer_wrong_length(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        self.assertFailed(peer.offer(0, raw=b"\x07\x01\x00\x00\x00"))

    @spec("RFC 4752", "3.1", "REQUIRED",
          "client verifies the server maximum buffer is 0 if no layer is offered")
    def test_no_layer_with_nonzero_maxbuf(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        self.assertFailed(peer.offer(LAYER_NONE, maxbuf=0x10000))

    @spec("RFC 4752", "3.1", "MUST",
          "client maximum buffer MUST be 0 if it chooses no security layer")
    def test_no_layer_choice_has_zero_maxbuf(self):
        peer = GssServerPeer(self.gss_client(max_ssf=0))
        peer.establish()
        r = peer.offer(LAYER_NONE, maxbuf=0)
        self.assertOk(r)
        choice = peer.ctx.unwrap(r.out).message
        self.assertEqual(choice[0], LAYER_NONE)
        self.assertEqual(choice[1:4], b"\0\0\0")

    @spec("RFC 4752", "3.1", "ABNF", "the authzid follows the 4 octets, with no NUL")
    def test_authzid_sent(self):
        peer = GssServerPeer(self.gss_client(authzid="admin"))
        peer.establish()
        r = peer.offer(LAYER_NONE, maxbuf=0)
        self.assertOk(r)
        self.assertEqual(peer.ctx.unwrap(r.out).message[4:], b"admin")

    @known_bug("S3", "GSS_Unwrap supplementary status (replay) is ignored")
    @spec("RFC 4752", "3.3", "MUST",
          "GSS_Unwrap status other than GSS_S_COMPLETE MUST be a fatal error")
    def test_replayed_packet_rejected(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        self.assertOk(peer.offer(LAYER_INTEGRITY))
        packet = frame(peer.ctx.wrap(b"pay $100", False).message)
        self.assertOk(peer.client.decode(packet))
        self.assertFailed(peer.client.decode(packet), "replayed packet was accepted")

    @known_bug("S6", "client always delegates its TGT in GSS_USE_CCACHE_STORE builds",
               only_if=config_defined("GSS_USE_CCACHE_STORE"))
    @spec("RFC 4752", "3.1", "INTEROP",
          "credentials are delegated only when the application asks for it")
    def test_no_delegation_by_default(self):
        peer = GssServerPeer(self.gss_client())
        peer.establish()
        self.assertNotIn(F.delegate_to_peer, peer.ctx.actual_flags)
        self.assertIsNone(peer.ctx.delegated_creds)
