"""GS2 (RFC 5801) wire-level conformance tests, using GS2-KRB5.

The initial client message is the GS2 header followed by the initial
context token with its RFC 2743 section 3.1 header removed (unless the
header starts with "F,").  The GS2 header, without "F,", plus any channel
binding data, is the application_data of the GSS-API channel bindings.
"""

import unittest

try:
    import gssapi
    import gssapi.raw
except ImportError:
    raise unittest.SkipTest("Python gssapi module not installed")

import krb5env
from sasltest import SANITIZED, SaslTestCase, known_bug, spec

MECH = "GS2-KRB5"
F = gssapi.RequirementFlag
KRB5_OID_TLV = bytes.fromhex("06092a864886f712010202")
TARGET = "%s@%s" % (krb5env.SERVICE, krb5env.HOST)
CB_NAME = "tls-exporter"
CB_DATA = bytes(range(32))

# The client passes GSS-API's empty output token (value NULL, length 0) to
# memcpy, which is undefined behavior; UBSan stops the driver there.
H30 = known_bug("H30", "client calls memcpy with a NULL source for an empty token",
                only_if=SANITIZED)


def der_length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def strip_token_header(token):
    """Remove the RFC 2743 section 3.1 header: 0x60, length, mech OID."""
    assert token[0] == 0x60, "not a framed initial context token"
    if token[1] < 0x80:
        i = 2
    else:
        i = 2 + (token[1] & 0x7f)
    assert token[i] == 0x06, "missing mechanism OID"
    oid_end = i + 2 + token[i + 1]
    assert token[i:oid_end] == KRB5_OID_TLV, "not a Kerberos token"
    return token[oid_end:]


def add_token_header(inner):
    body = KRB5_OID_TLV + inner
    return b"\x60" + der_length(len(body)) + body


def bindings(gs2_header, cb_data=b""):
    """GSS-API channel bindings for a GS2 header (RFC 5801 section 5.1)."""
    if gs2_header.startswith(b"F,"):
        gs2_header = gs2_header[2:]
    return gssapi.raw.ChannelBindings(application_data=gs2_header + cb_data)


class Gs2ClientPeer:
    """Plays the GS2 client against the library's server."""

    def __init__(self, server, gs2_header=b"n,,", cb_data=b"",
                 flags=(F.mutual_authentication, F.out_of_sequence_detection),
                 keep_header=False):
        self.server = server
        self.gs2_header = gs2_header
        self.keep_header = keep_header
        self.ctx = gssapi.SecurityContext(
            name=gssapi.Name(TARGET, gssapi.NameType.hostbased_service),
            usage="initiate", mech=gssapi.MechType.kerberos, flags=list(flags),
            channel_bindings=bindings(gs2_header, cb_data))

    def run(self):
        token = self.ctx.step()
        if not self.keep_header:
            token = strip_token_header(token)
        r = self.server.start(self.gs2_header + token)
        while r.cont:
            token = self.ctx.step(r.out) if r.out else None
            r = self.server.step(token or b"")
        if r.ok and r.out:
            self.ctx.step(r.out)
        return r


class Gs2Server(SaslTestCase):

    def setUp(self):
        super().setUp()
        krb5env.require()

    def gs2_server(self, mech=MECH, **kw):
        kw.setdefault("success_data", True)
        # The library looks up the authenticated principal in the password
        # store and fails with SASL_NOUSER when it isn't there (see
        # test_no_account_required), so give these protocol tests one.
        kw.setdefault("users", {krb5env.USER: "unused"})
        s = self.server(mech, **kw)
        if MECH not in s.mechs and MECH + "-PLUS" not in s.mechs:
            self.skipTest("%s not available" % MECH)
        return s

    @known_bug("H29", "server fails with SASL_NOUSER unless the password store "
               "has an entry for the Kerberos principal")
    @spec("RFC 5801", "4", "INTEROP",
          "the GSS-API mechanism authenticates the user; no password entry is needed")
    def test_no_account_required(self):
        peer = Gs2ClientPeer(self.gs2_server(users={"someone-else": "x"}))
        self.assertOk(peer.run())

    @spec("RFC 5801", "4", "MUST", "server authenticates a GS2-KRB5 client")
    def test_valid_exchange(self):
        peer = Gs2ClientPeer(self.gs2_server())
        r = peer.run()
        self.assertOk(r)
        self.assertEqual(r.user, b"user")
        self.assertTrue(peer.ctx.complete, "mutual authentication didn't complete")

    @spec("RFC 5801", "4", "MUST",
          "with F, the token keeps its RFC 2743 header and the server MUST NOT re-add one")
    def test_nonstandard_flag(self):
        peer = Gs2ClientPeer(self.gs2_server(), gs2_header=b"F,n,,", keep_header=True)
        self.assertOk(peer.run())

    @known_bug("I4", "server requires the SEQUENCE per-message flag")
    @spec("RFC 5801", "8", "SHOULD NOT",
          "per-message req_flags are irrelevant; clients SHOULD NOT set them")
    def test_client_without_sequence_flag(self):
        peer = Gs2ClientPeer(self.gs2_server(), flags=(F.mutual_authentication,))
        self.assertOk(peer.run())

    # --- GS2 header ---

    @known_bug("H7", "an unknown gs2-cb-flag is treated as n")
    @spec("RFC 5801", "7", "MUST",
          "authentication MUST NOT succeed if the GS2 header doesn't match the ABNF")
    def test_unknown_cb_flag(self):
        peer = Gs2ClientPeer(self.gs2_server(), gs2_header=b"x,,")
        self.assertFailed(peer.run())

    @known_bug("H8", "NUL in the authzid is accepted and truncates it")
    @spec("RFC 5801", "4", "ABNF", "UTF8-1-safe excludes NUL in the authzid")
    def test_authzid_with_nul(self):
        peer = Gs2ClientPeer(self.gs2_server(), gs2_header=b"n,a=user\0junk,")
        self.assertFailed(peer.run())

    @spec("RFC 5801", "4", "MUST", "a= requires authorization to act as that identity")
    def test_authzid_not_permitted(self):
        peer = Gs2ClientPeer(self.gs2_server(), gs2_header=b"n,a=admin,")
        self.assertFailed(peer.run())

    @spec("RFC 5801", "4", "MUST", "a= values are unescaped (=2C, =3D)")
    def test_authzid_escaping(self):
        server = self.gs2_server(proxies=[("user", "ad,m=in")])
        peer = Gs2ClientPeer(server, gs2_header=b"n,a=ad=2Cm=3Din,")
        r = peer.run()
        self.assertOk(r)
        self.assertEqual(r.user, b"ad,m=in")
        self.assertEqual(r.authuser, b"user")

    @spec("RFC 5801", "4", "ABNF", "an invalid escape in the authzid fails")
    def test_authzid_bad_escape(self):
        peer = Gs2ClientPeer(self.gs2_server(), gs2_header=b"n,a=us=41er,")
        self.assertFailed(peer.run())

    # --- channel binding ---

    def cb_server(self, critical=False, data=CB_DATA):
        return self.gs2_server(mech=MECH + "-PLUS", cbinding=(CB_NAME, data),
                               critical=critical)

    @spec("RFC 5801", "5", "MUST", "server with channel binding offers the -PLUS variant")
    def test_plus_advertised(self):
        self.assertIn(MECH + "-PLUS", self.cb_server().mechs)

    @spec("RFC 5801", "5", "MUST", "p= with matching channel bindings succeeds")
    def test_p_matching_binding(self):
        header = ("p=%s,," % CB_NAME).encode()
        peer = Gs2ClientPeer(self.cb_server(), gs2_header=header, cb_data=CB_DATA)
        self.assertOk(peer.run())

    @spec("RFC 5801", "5", "MUST", "p= with different channel binding data fails")
    def test_p_mismatched_binding(self):
        header = ("p=%s,," % CB_NAME).encode()
        peer = Gs2ClientPeer(self.cb_server(), gs2_header=header, cb_data=b"\xff" * 32)
        self.assertFailed(peer.run())

    @spec("RFC 5801", "5", "MUST",
          "server MUST fail if the client sent y and the server supports binding")
    def test_y_downgrade_detected(self):
        peer = Gs2ClientPeer(self.gs2_server(cbinding=(CB_NAME, CB_DATA)), gs2_header=b"y,,")
        self.assertFailed(peer.run())

    @spec("RFC 5801", "5", "MUST", "n is rejected when binding is required")
    def test_n_rejected_when_critical(self):
        peer = Gs2ClientPeer(self.cb_server(critical=True))
        self.assertFailed(peer.run())


class Gs2ServerPeer:
    """Plays the GS2 server against the library's client."""

    def __init__(self, client, cb_data=b""):
        self.client = client
        self.cb_data = cb_data

    def run(self):
        message = self.client.first.out
        flag_end = message.index(b",")
        header_end = message.index(b",", flag_end + 1) + 1
        self.gs2_header = message[:header_end]
        token = message[header_end:]
        if not self.gs2_header.startswith(b"F,"):
            token = add_token_header(token)
        cb_data = self.cb_data if self.gs2_header.startswith(b"p=") else b""
        self.ctx = gssapi.SecurityContext(
            usage="accept", creds=gssapi.Credentials(usage="accept"),
            channel_bindings=bindings(self.gs2_header, cb_data))
        out = self.ctx.step(token)
        r = self.client.step(out or b"")
        if r.cont:
            r = self.client.step(None)
        return r


class Gs2Client(SaslTestCase):

    def setUp(self):
        super().setUp()
        krb5env.require()

    def gs2_client(self, mechlist=MECH, **kw):
        # Without an authentication name the GS2 client fails instead of
        # falling back to the default credential, unlike GSSAPI.
        kw.setdefault("authname", krb5env.USER)
        c = self.client(mechlist, **kw)
        if c.first.name == "SASL_NOMECH":
            self.skipTest("%s not available" % MECH)
        self.assertContinue(c.first)
        return c

    @H30
    @spec("RFC 5801", "4", "MUST",
          "initial message is the GS2 header plus the token without its RFC 2743 header")
    def test_valid_exchange(self):
        peer = Gs2ServerPeer(self.gs2_client())
        r = peer.run()
        self.assertEqual(peer.gs2_header, b"n,,")
        self.assertTrue(peer.ctx.complete)
        self.assertOk(r)

    @H30
    @spec("RFC 5801", "8", "MUST", "client requests mutual authentication")
    def test_mutual_requested(self):
        peer = Gs2ServerPeer(self.gs2_client())
        peer.run()
        self.assertIn(F.mutual_authentication, peer.ctx.actual_flags)

    @known_bug("I4", "client requests the SEQUENCE per-message flag")
    @spec("RFC 5801", "8", "SHOULD NOT",
          "implementations SHOULD NOT set the per-message req_flags")
    def test_no_per_message_flags(self):
        peer = Gs2ServerPeer(self.gs2_client())
        peer.run()
        self.assertNotIn(F.out_of_sequence_detection, peer.ctx.actual_flags)

    @H30
    @spec("RFC 5801", "4", "MUST", "a= carries the authorization identity")
    def test_authzid_in_header(self):
        peer = Gs2ServerPeer(self.gs2_client(authzid="ad,min"))
        peer.run()
        self.assertEqual(peer.gs2_header, b"n,a=ad=2Cmin,")

    @H30
    @spec("RFC 5801", "5", "MUST",
          "client with channel binding picks -PLUS and binds the GS2 header and data")
    def test_selects_plus(self):
        c = self.gs2_client("%s %s-PLUS" % (MECH, MECH), cbinding=(CB_NAME, CB_DATA))
        peer = Gs2ServerPeer(c, cb_data=CB_DATA)
        r = peer.run()
        self.assertEqual(peer.gs2_header, ("p=%s,," % CB_NAME).encode())
        self.assertTrue(peer.ctx.complete)
        self.assertOk(r)

    @spec("RFC 5801", "5", "MUST NOT",
          "client that supports binding MUST NOT send n when the server appears not to")
    def test_y_with_single_mechanism(self):
        c = self.gs2_client(MECH, cbinding=(CB_NAME, CB_DATA))
        self.assertTrue(c.first.out.startswith(b"y,"),
                        "GS2 header %r" % c.first.out[:16])
