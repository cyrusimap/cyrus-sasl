"""SCRAM interoperability with an independent implementation (scramp).

scramp (https://github.com/tlocke/scramp) is a separate Python SCRAM
implementation that applies SASLprep, so it gives a second opinion on the
protocol beyond this suite's own SCRAM peer.  Its client runs against the
library's server and its server against the library's client, for each
SCRAM variant both support, with and without channel binding from real
TLS sessions.  Skipped if scramp isn't installed.

scramp doesn't support tls-exporter, so these use tls-unique and
tls-server-end-point; test_tls_cbind.py covers tls-exporter.
"""

import os
import unittest

try:
    import scramp
except ImportError:
    raise unittest.SkipTest("scramp not installed")

import tlsenv
from sasltest import SaslTestCase, known_bug, spec

USER = "alice"
PASSWORD = "pencil"
SCRAMP_MECHS = [m for m in ("SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512")
                if m in getattr(scramp, "MECHANISMS", (m,))]


def scramp_supports(mech):
    try:
        scramp.ScramMechanism(mech)
        return True
    except Exception:
        return False


class ScrampInterop(SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech("SCRAM-SHA-256")

    # --- scramp client, library server ---

    def scramp_client_run(self, mech, password=PASSWORD, stored=PASSWORD,
                          cb=None, server_cb=None):
        server = self.server(mech, users={USER: stored}, success_data=True,
                             cbinding=server_cb)
        if mech not in server.mechs:
            self.skipTest("%s not offered by this build" % mech)
        client = scramp.ScramClient([mech], USER, password, channel_binding=cb)
        r = server.start(client.get_client_first().encode())
        if not r.cont:
            return r, client
        client.set_server_first(r.out.decode())
        r = server.step(client.get_client_final().encode())
        if r.ok:
            client.set_server_final(r.out.decode())  # raises on a bad v=
        return r, client

    def check_scramp_client(self, mech):
        if not scramp_supports(mech):
            self.skipTest("scramp doesn't support %s" % mech)
        r, _ = self.scramp_client_run(mech)
        self.assertOk(r)
        self.assertEqual(r.user, USER.encode())

    @spec("RFC 5802", "5", "INTEROP", "scramp client authenticates (SCRAM-SHA-1)")
    def test_scramp_client_sha1(self):
        self.check_scramp_client("SCRAM-SHA-1")

    @spec("RFC 7677", "3", "INTEROP", "scramp client authenticates (SCRAM-SHA-256)")
    def test_scramp_client_sha256(self):
        self.check_scramp_client("SCRAM-SHA-256")

    @spec("RFC 5802", "5", "INTEROP", "scramp client authenticates (SCRAM-SHA-512)")
    def test_scramp_client_sha512(self):
        self.check_scramp_client("SCRAM-SHA-512")

    @spec("RFC 5802", "5", "INTEROP", "scramp client fails with the wrong password")
    def test_scramp_client_wrong_password(self):
        r, _ = self.scramp_client_run("SCRAM-SHA-256", password="wrong")
        self.assertFailed(r)

    def scramp_client_plus(self, cb_type):
        tlsenv.require()
        mech = "SCRAM-SHA-256-PLUS"
        if not scramp_supports(mech):
            self.skipTest("scramp doesn't support %s" % mech)
        c_data, s_data = tlsenv.channel_bindings(cb_type)
        r, _ = self.scramp_client_run(mech, cb=(cb_type, c_data),
                                      server_cb=(cb_type, s_data))
        self.assertOk(r)

    @spec("RFC 5929", "3", "INTEROP", "scramp client with tls-unique binding")
    def test_scramp_client_plus_tls_unique(self):
        self.scramp_client_plus("tls-unique")

    @spec("RFC 5929", "4", "INTEROP", "scramp client with tls-server-end-point binding")
    def test_scramp_client_plus_tls_server_end_point(self):
        self.scramp_client_plus("tls-server-end-point")

    @known_bug("I2", "the library doesn't apply SASLprep; scramp does")
    @spec("RFC 5802", "2.2", "INTEROP",
          "a non-ASCII password that SASLprep changes still authenticates")
    def test_scramp_client_saslprep_password(self):
        password = "pen­cil"  # SASLprep removes the soft hyphen
        r, _ = self.scramp_client_run("SCRAM-SHA-256", password=password,
                                      stored=password)
        self.assertOk(r)

    # --- library client, scramp server ---

    def scramp_server_run(self, mech, password=PASSWORD, stored=PASSWORD,
                          cb=None, server_cb=None, mechlist=None):
        m = scramp.ScramMechanism(mech)
        auth_info = m.make_auth_info(stored, iteration_count=4096,
                                     salt=os.urandom(16))
        server = m.make_server(lambda user: auth_info, channel_binding=server_cb)
        client = self.client(mechlist or mech, authname=USER, password=password,
                             cbinding=cb)
        if client.first.name == "SASL_NOMECH":
            self.skipTest("%s not offered by this build" % mech)
        self.assertContinue(client.first)
        server.set_client_first(client.first.out.decode())
        r = client.step(server.get_server_first().encode())
        if not r.cont and not r.ok:
            return r
        try:
            server.set_client_final(r.out.decode())
        except scramp.ScramException as e:
            self.fail("scramp server rejected the client-final message: %s" % e)
        return client.step(server.get_server_final().encode())

    def check_scramp_server(self, mech):
        if not scramp_supports(mech):
            self.skipTest("scramp doesn't support %s" % mech)
        self.assertOk(self.scramp_server_run(mech))

    @spec("RFC 5802", "5", "INTEROP", "client authenticates to scramp (SCRAM-SHA-1)")
    def test_scramp_server_sha1(self):
        self.check_scramp_server("SCRAM-SHA-1")

    @spec("RFC 7677", "3", "INTEROP", "client authenticates to scramp (SCRAM-SHA-256)")
    def test_scramp_server_sha256(self):
        self.check_scramp_server("SCRAM-SHA-256")

    @spec("RFC 5802", "5", "INTEROP", "client authenticates to scramp (SCRAM-SHA-512)")
    def test_scramp_server_sha512(self):
        self.check_scramp_server("SCRAM-SHA-512")

    def scramp_server_plus(self, cb_type):
        tlsenv.require()
        mech = "SCRAM-SHA-256-PLUS"
        if not scramp_supports(mech):
            self.skipTest("scramp doesn't support %s" % mech)
        c_data, s_data = tlsenv.channel_bindings(cb_type)
        r = self.scramp_server_run(mech, cb=(cb_type, c_data),
                                   server_cb=(cb_type, s_data),
                                   mechlist="SCRAM-SHA-256 SCRAM-SHA-256-PLUS")
        self.assertOk(r)

    @spec("RFC 5929", "3", "INTEROP", "client authenticates to scramp with tls-unique")
    def test_scramp_server_plus_tls_unique(self):
        self.scramp_server_plus("tls-unique")

    @spec("RFC 5929", "4", "INTEROP",
          "client authenticates to scramp with tls-server-end-point")
    def test_scramp_server_plus_tls_server_end_point(self):
        self.scramp_server_plus("tls-server-end-point")

    @known_bug("I2", "the library doesn't apply SASLprep; scramp does")
    @spec("RFC 5802", "2.2", "INTEROP",
          "a non-ASCII password that SASLprep changes still authenticates")
    def test_scramp_server_saslprep_password(self):
        password = "pen­cil"
        self.assertOk(self.scramp_server_run("SCRAM-SHA-256", password=password,
                                             stored=password))
