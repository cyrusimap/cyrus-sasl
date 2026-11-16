"""PLAIN (RFC 4616) wire-level conformance tests.

message = [authzid] UTF8NUL authcid UTF8NUL passwd
"""

from sasltest import SaslTestCase, known_bug, spec

USERS = {"alice": "secret", "bob": "hunter2"}


def plain(authzid, authcid, passwd):
    return b"\0".join(s.encode("utf-8") if isinstance(s, str) else s
                      for s in (authzid, authcid, passwd))


class PlainServer(SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech("PLAIN")

    def run_plain(self, message, **kw):
        kw.setdefault("users", USERS)
        return self.server("PLAIN", **kw).start(message)

    # --- successful authentication ---

    @spec("RFC 4616", "2", "MUST", "server verifies authcid and passwd")
    def test_valid_credentials(self):
        r = self.run_plain(plain("", "alice", "secret"))
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")
        self.assertEqual(r.authuser, b"alice")

    @spec("RFC 4422", "5", "MUST", "no additional data with the success outcome")
    def test_no_additional_data_on_success(self):
        r = self.run_plain(plain("", "alice", "secret"))
        self.assertOk(r)
        self.assertFalse(r.out, "PLAIN server sent data with success: %r" % r.out)

    @spec("RFC 4616", "2", "MUST", "authzid equal to authcid is accepted")
    def test_authzid_same_as_authcid(self):
        r = self.run_plain(plain("alice", "alice", "secret"))
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")

    @spec("RFC 4616", "2", "MUST", "server verifies the authcid may act as the authzid")
    def test_authzid_permitted(self):
        r = self.run_plain(plain("bob", "alice", "secret"),
                           proxies=[("alice", "bob")])
        self.assertOk(r)
        self.assertEqual(r.user, b"bob")
        self.assertEqual(r.authuser, b"alice")

    @spec("RFC 4616", "2", "ABNF", "authcid and passwd may each be up to 255 octets")
    def test_255_octet_fields(self):
        name, password = "u" * 255, "p" * 255
        r = self.run_plain(plain("", name, password), users={name: password})
        self.assertOk(r)
        self.assertEqual(r.user, name.encode())

    # --- authentication and authorization failures ---

    @spec("RFC 4616", "2", "MUST", "wrong password fails")
    def test_wrong_password(self):
        self.assertFailed(self.run_plain(plain("", "alice", "wrong")))

    @spec("RFC 4616", "2", "MUST", "unknown user fails")
    def test_unknown_user(self):
        self.assertFailed(self.run_plain(plain("", "mallory", "secret")))

    @spec("RFC 4616", "2", "MUST", "server verifies the authcid may act as the authzid")
    def test_authzid_not_permitted(self):
        self.assertFailed(self.run_plain(plain("bob", "alice", "secret")))

    @spec("RFC 4616", "2", "ABNF", "authcid = 1*SAFE")
    def test_empty_authcid(self):
        self.assertFailed(self.run_plain(plain("", "", "secret")))

    @known_bug("S2", "empty password is passed to the verifier")
    @spec("RFC 4616", "2", "SHALL",
          "if preparation results in an empty string, verification SHALL fail")
    def test_empty_password(self):
        r = self.run_plain(plain("", "carol", ""), users={"carol": ""})
        self.assertFailed(r)

    @spec("RFC 4422", "3.4.1", "MUST",
          "a non-empty authzid requests that exact identity")
    def test_whitespace_authzid(self):
        r = self.run_plain(plain(" ", "alice", "secret"))
        self.assertFailed(r, "authzid ' ' was accepted as %r" % r.user)

    def test_authzid_leading_whitespace(self):
        # Regression test for the canonicalization bug behind S1, which also
        # rejected names whose leading-space count equals their trimmed
        # length as "All-whitespace".  Surrounding whitespace is trimmed.
        r = self.run_plain(plain("  ab", "ab", "secret"), users={"ab": "secret"})
        self.assertOk(r)
        self.assertEqual(r.user, b"ab")

    # --- message syntax ---

    @spec("RFC 4616", "2", "ABNF", "message needs two NUL separators")
    def test_missing_separator(self):
        self.assertFailed(self.run_plain(b"alice\0secret"))

    @spec("RFC 4616", "2", "ABNF", "no data after passwd")
    def test_trailing_nul(self):
        self.assertFailed(self.run_plain(plain("", "alice", "secret") + b"\0"))

    @spec("RFC 4616", "2", "ABNF", "NUL is not allowed in passwd")
    def test_extra_field(self):
        self.assertFailed(self.run_plain(plain("", "alice", "secret") + b"\0extra"))

    @spec("RFC 4616", "2", "ABNF", "an empty message is not a valid PLAIN message")
    def test_empty_initial_response(self):
        self.assertFailed(self.run_plain(b""))

    # --- exchange structure ---

    @spec("RFC 4422", "5", "MUST",
          "without an initial response, the server sends an empty challenge")
    def test_no_initial_response(self):
        s = self.server("PLAIN", users=USERS)
        r = s.start(None)
        self.assertContinue(r)
        self.assertEqual(r.out or b"", b"")
        r = s.step(plain("", "alice", "secret"))
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")


class PlainClient(SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech("PLAIN")

    @spec("RFC 4616", "2", "ABNF", "initial response is NUL authcid NUL passwd")
    def test_message_without_authzid(self):
        c = self.client("PLAIN", authname="alice", password="secret")
        self.assertOk(c.first)
        self.assertEqual(c.first.mech, "PLAIN")
        self.assertEqual(c.first.out, b"\0alice\0secret")

    @spec("RFC 4616", "2", "ABNF", "initial response is authzid NUL authcid NUL passwd")
    def test_message_with_authzid(self):
        c = self.client("PLAIN", authname="alice", authzid="bob", password="secret")
        self.assertOk(c.first)
        self.assertEqual(c.first.out, b"bob\0alice\0secret")

    @spec("RFC 4422", "5", "MUST",
          "without an initial response, the client answers the empty challenge")
    def test_empty_challenge(self):
        c = self.client("PLAIN", authname="alice", password="secret",
                        no_initial_response=True)
        self.assertContinue(c.first)
        self.assertFalse(c.first.out)
        r = c.step(b"")
        self.assertOk(r)
        self.assertEqual(r.out, b"\0alice\0secret")

    @known_bug("H22", "client ignores a non-empty first challenge")
    @spec("RFC 4422", "5", "MUST",
          "for a client-first mechanism, the first server challenge MUST be empty")
    def test_nonempty_challenge_rejected(self):
        c = self.client("PLAIN", authname="alice", password="secret",
                        no_initial_response=True)
        self.assertContinue(c.first)
        self.assertFailed(c.step(b"unexpected"))

    @spec("RFC 4422", "3.6", "MUST",
          "data after the exchange is complete is a protocol error")
    def test_data_after_success_rejected(self):
        c = self.client("PLAIN", authname="alice", password="secret")
        self.assertOk(c.first)
        self.assertFailed(c.step(b"more"))
