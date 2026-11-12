"""Channel binding with data from real TLS sessions.

The other channel binding tests use synthetic bytes, which is enough for
the library (it treats binding data as opaque).  These derive the data
from real TLS handshakes (tlsenv.py), the way an application would, for
each binding type: tls-exporter (RFC 9266), tls-unique and
tls-server-end-point (RFC 5929).
"""

import krb5env
import tlsenv
from sasltest import SANITIZED, SaslTestCase, known_bug, spec
from test_scram import PASSWORD, USER, USERS, ScramClientHelpers, ScramPeer

MECH = "SCRAM-SHA-256"
PLUS = MECH + "-PLUS"


def relay(client, server):
    """Run an exchange between a library client and a library server."""
    r = server.start(client.first.out)
    c = client.first
    while r.cont:
        c = client.step(r.out if r.out is not None else b"")
        if c.failed:
            return c, r
        r = server.step(c.out if c.out is not None else b"")
    if r.ok and r.out:
        c = client.step(r.out)
    elif r.ok and c.cont:
        c = client.step(None)
    return c, r


class TlsScramChannelBinding(SaslTestCase):

    def setUp(self):
        super().setUp()
        tlsenv.require()
        self.require_mech(MECH)

    def pair(self, cb_type, client_data, server_data):
        server = self.server(PLUS, users=USERS, success_data=True,
                             cbinding=(cb_type, server_data))
        client = self.client("%s %s" % (MECH, PLUS), authname=USER,
                             password=PASSWORD, cbinding=(cb_type, client_data))
        self.assertContinue(client.first)
        self.assertTrue(client.first.out.startswith(("p=%s," % cb_type).encode()),
                        "client didn't use %s: %r" % (cb_type, client.first.out[:24]))
        return client, server

    def matching(self, cb_type):
        c_data, s_data = tlsenv.channel_bindings(cb_type)
        self.assertEqual(c_data, s_data)
        c, r = relay(*self.pair(cb_type, c_data, s_data))
        self.assertOk(r)
        self.assertOk(c)

    def mismatched(self, cb_type):
        c_data, _ = tlsenv.channel_bindings(cb_type)
        _, s_data = tlsenv.channel_bindings(cb_type)  # a different session
        self.assertNotEqual(c_data, s_data)
        c, r = relay(*self.pair(cb_type, c_data, s_data))
        self.assertFailed(r if not r.cont else c,
                          "authentication succeeded across two TLS sessions")

    @spec("RFC 9266", "2", "MUST", "SCRAM-PLUS succeeds with matching tls-exporter data")
    def test_tls_exporter(self):
        self.matching("tls-exporter")

    @spec("RFC 5929", "3", "MUST", "SCRAM-PLUS succeeds with matching tls-unique data")
    def test_tls_unique(self):
        self.matching("tls-unique")

    @spec("RFC 5929", "4", "MUST",
          "SCRAM-PLUS succeeds with matching tls-server-end-point data")
    def test_tls_server_end_point(self):
        self.matching("tls-server-end-point")

    @spec("RFC 5802", "6", "MUST",
          "tls-exporter data from a different TLS session fails authentication")
    def test_tls_exporter_other_session(self):
        self.mismatched("tls-exporter")

    @spec("RFC 5802", "6", "MUST",
          "tls-unique data from a different TLS session fails authentication")
    def test_tls_unique_other_session(self):
        self.mismatched("tls-unique")

    @spec("RFC 9266", "2", "MUST",
          "independent client computes c= from real tls-exporter data")
    def test_independent_client_tls_exporter(self):
        c_data, s_data = tlsenv.channel_bindings("tls-exporter")
        server = self.server(PLUS, users=USERS, success_data=True,
                             cbinding=("tls-exporter", s_data))
        p = ScramPeer(server, mech=PLUS, gs2_header="p=tls-exporter,,",
                      cbind_data=c_data)
        self.assertContinue(p.first())
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.out.decode(), p.expected_verifier())


class TlsScramClientChannelBinding(ScramClientHelpers):
    """The library client against the independent server, real TLS data."""

    def setUp(self):
        super().setUp()
        tlsenv.require()

    @spec("RFC 9266", "2", "MUST",
          "client sends c= built from real tls-exporter data")
    def test_client_tls_exporter(self):
        c_data, s_data = tlsenv.channel_bindings("tls-exporter")
        c = self.start("%s %s" % (MECH, PLUS), cbinding=("tls-exporter", c_data))
        self.assertEqual(self.gs2_header, "p=tls-exporter,,")
        r = self.server_first(c)
        scram, auth = self.check_final(r, mech=PLUS, cbind_data=s_data)
        self.assertOk(c.step(self.verifier(scram, auth).encode()))


class TlsGs2ChannelBinding(SaslTestCase):

    def setUp(self):
        super().setUp()
        tlsenv.require()
        krb5env.require()

    @known_bug("H30", "client calls memcpy with a NULL source for an empty token",
               only_if=SANITIZED)
    @spec("RFC 5801", "5", "MUST",
          "GS2-KRB5-PLUS succeeds with matching tls-exporter data")
    def test_gs2_tls_exporter(self):
        c_data, s_data = tlsenv.channel_bindings("tls-exporter")
        server = self.server("GS2-KRB5-PLUS", success_data=True,
                             users={krb5env.USER: "unused"},
                             cbinding=("tls-exporter", s_data))
        if "GS2-KRB5-PLUS" not in server.mechs:
            self.skipTest("GS2-KRB5 not available")
        client = self.client("GS2-KRB5 GS2-KRB5-PLUS", authname=krb5env.USER,
                             cbinding=("tls-exporter", c_data))
        self.assertTrue(client.first.out.startswith(b"p=tls-exporter,"))
        c, r = relay(client, server)
        self.assertOk(r)

    @spec("RFC 5801", "5", "MUST",
          "GS2-KRB5-PLUS fails with tls-exporter data from a different session")
    def test_gs2_tls_exporter_other_session(self):
        c_data, _ = tlsenv.channel_bindings("tls-exporter")
        _, s_data = tlsenv.channel_bindings("tls-exporter")
        server = self.server("GS2-KRB5-PLUS", success_data=True,
                             users={krb5env.USER: "unused"},
                             cbinding=("tls-exporter", s_data))
        if "GS2-KRB5-PLUS" not in server.mechs:
            self.skipTest("GS2-KRB5 not available")
        client = self.client("GS2-KRB5 GS2-KRB5-PLUS", authname=krb5env.USER,
                             cbinding=("tls-exporter", c_data))
        c, r = relay(client, server)
        self.assertFailed(r if not r.cont else c)
