"""ANONYMOUS (RFC 4505) wire-level conformance tests.

message = [ email / token ]   ; optional trace information
token   = 1*255TCHAR          ; no "@"
"""

import re

from sasltest import SaslTestCase, known_bug, spec

SASL_SEC_NOANONYMOUS = 0x0010

# RFC 4505 section 2: a token is 1..255 characters and has no "@".  The
# email alternative is an RFC 2822 addr-spec; this simplified pattern is
# enough to tell one apart from the "<user>@<host>@<host>" shape.
TOKEN_RE = re.compile(r"^[^@]{1,255}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")


def valid_trace(message):
    text = message.decode("utf-8")
    return text == "" or bool(TOKEN_RE.match(text)) or bool(EMAIL_RE.match(text))


class AnonymousServer(SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech("ANONYMOUS")

    def server(self, mech, **kw):
        # The library looks up the identity "anonymous" in the password
        # store and fails with SASL_NOUSER when it isn't there (see
        # test_no_account_required), so give these protocol tests one.
        kw.setdefault("users", {"anonymous": "unused"})
        return super().server(mech, **kw)

    @known_bug("H28", "ANONYMOUS fails with SASL_NOUSER unless the password "
               "store has an 'anonymous' account")
    @spec("RFC 4505", "3", "INTEROP",
          "ANONYMOUS doesn't depend on a user account in the password store")
    def test_no_account_required(self):
        r = super().server("ANONYMOUS", users={"alice": "secret"}).start(b"sirhc")
        self.assertOk(r)

    @spec("RFC 4505", "2", "ABNF", "the trace message is optional")
    def test_empty_message(self):
        r = self.server("ANONYMOUS").start(b"")
        self.assertOk(r)

    @spec("RFC 4505", "2", "ABNF", "a token trace is accepted")
    def test_token_trace(self):
        self.assertOk(self.server("ANONYMOUS").start(b"sirhc"))

    @spec("RFC 4505", "2", "ABNF", "an email trace is accepted")
    def test_email_trace(self):
        self.assertOk(self.server("ANONYMOUS").start(b"sirhc@example.com"))

    @spec("RFC 4505", "2", "ABNF", "a token may be up to 1020 octets (255 characters)")
    def test_1020_octet_trace(self):
        trace = ("\U0001F600" * 255).encode("utf-8")
        self.assertEqual(len(trace), 1020)
        self.assertOk(self.server("ANONYMOUS").start(trace))

    @spec("RFC 4505", "3", "MUST",
          "trace information is not an identity; the client is not authorized as it")
    def test_trace_is_not_identity(self):
        r = self.server("ANONYMOUS").start(b"root")
        self.assertOk(r)
        self.assertNotEqual(r.user, b"root")
        self.assertEqual(r.user, b"anonymous")

    @spec("RFC 4422", "5", "MUST", "no additional data with the success outcome")
    def test_no_additional_data_on_success(self):
        r = self.server("ANONYMOUS").start(b"sirhc")
        self.assertOk(r)
        self.assertFalse(r.out)

    @spec("RFC 4422", "5", "MUST",
          "without an initial response, the server sends an empty challenge")
    def test_no_initial_response(self):
        s = self.server("ANONYMOUS")
        r = s.start(None)
        self.assertContinue(r)
        self.assertEqual(r.out or b"", b"")
        self.assertOk(s.step(b"sirhc"))

    @spec("RFC 4505", "5", "SHOULD",
          "a server that doesn't allow anonymous access doesn't offer ANONYMOUS")
    def test_noanonymous_policy(self):
        s = self.server("ANONYMOUS", secflags=SASL_SEC_NOANONYMOUS)
        self.assertNotIn("ANONYMOUS", s.mechs)
        self.assertFailed(s.start(b"sirhc"))


class AnonymousClient(SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech("ANONYMOUS")

    @known_bug("H18", "client always sends <user>@<hostname> as the trace")
    @spec("RFC 4505", "5", "SHOULD",
          "the client should offer the option of supplying no trace information")
    def test_no_trace_by_default(self):
        c = self.client("ANONYMOUS")
        self.assertOk(c.first)
        self.assertEqual(c.first.out, b"")

    @known_bug("H18", "client appends @<hostname> to an email trace")
    @spec("RFC 4505", "2", "ABNF", "message = [ email / token ]")
    def test_email_trace_sent_as_given(self):
        c = self.client("ANONYMOUS", authzid="sirhc@example.com")
        self.assertOk(c.first)
        self.assertTrue(valid_trace(c.first.out),
                        "trace %r matches neither email nor token" % c.first.out)
        self.assertEqual(c.first.out, b"sirhc@example.com")

    @spec("RFC 4422", "5", "MUST",
          "for a client-first mechanism, the first server challenge MUST be empty")
    def test_nonempty_challenge_rejected(self):
        c = self.client("ANONYMOUS", no_initial_response=True)
        self.assertContinue(c.first)
        self.assertFailed(c.step(b"unexpected"))

    @spec("RFC 4422", "3.6", "MUST",
          "data after the exchange is complete is a protocol error")
    def test_data_after_success_rejected(self):
        c = self.client("ANONYMOUS")
        self.assertOk(c.first)
        self.assertFailed(c.step(b"more"))
