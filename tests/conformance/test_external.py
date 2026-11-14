"""EXTERNAL (RFC 4422 Appendix A) wire-level conformance tests.

The client's only message is an optional authorization identity:

    external-initial-resp = authz-id-string
    authz-id-string       = *( UTF8-char-no-nul )

The authentication identity comes from outside SASL (for example a TLS
client certificate); the drivers set it with SASL_AUTH_EXTERNAL.
"""

from sasltest import SaslTestCase, known_bug, spec

EXT_ID = "alice"


class ExternalServer(SaslTestCase):

    def ext_server(self, **kw):
        kw.setdefault("external", EXT_ID)
        s = self.server("EXTERNAL", **kw)
        if "EXTERNAL" not in s.mechs:
            self.skipTest("EXTERNAL not available")
        return s

    @spec("RFC 4422", "A.1", "MUST",
          "an empty authzid means the identity derived from the external credentials")
    def test_empty_authzid(self):
        r = self.ext_server().start(b"")
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")
        self.assertEqual(r.authuser, b"alice")

    @spec("RFC 4422", "A.1", "MUST", "authzid equal to the external identity is accepted")
    def test_authzid_same_as_external(self):
        r = self.ext_server().start(b"alice")
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")

    @spec("RFC 4422", "A.1", "MUST",
          "a non-empty authzid the client isn't authorized for fails")
    def test_authzid_not_permitted(self):
        self.assertFailed(self.ext_server().start(b"bob"))

    @spec("RFC 4422", "A.1", "MUST", "a non-empty authzid is honored when authorized")
    def test_authzid_permitted(self):
        r = self.ext_server(proxies=[("alice", "bob")]).start(b"bob")
        self.assertOk(r)
        self.assertEqual(r.user, b"bob")
        self.assertEqual(r.authuser, b"alice")

    @spec("RFC 4422", "A.1", "ABNF", "authz-id-string = *( UTF8-char-no-nul )")
    def test_authzid_with_nul_rejected(self):
        # Rejected only because the test's proxy policy compares lengths;
        # see finding H23 for a policy that compares C strings.
        r = self.ext_server(proxies=[("alice", "bob")]).start(b"bob\0junk")
        self.assertFailed(r)

    @known_bug("S1", "whitespace-only authzid is canonicalized to an empty identity")
    @spec("RFC 4422", "3.4.1", "MUST",
          "a non-empty authzid requests that exact identity")
    def test_whitespace_authzid(self):
        r = self.ext_server().start(b" ")
        self.assertFailed(r, "authzid ' ' was accepted as %r" % r.user)

    @spec("RFC 4422", "A.1", "MUST",
          "EXTERNAL is not offered without external authentication")
    def test_unavailable_without_external_identity(self):
        s = self.server("EXTERNAL")
        self.assertNotIn("EXTERNAL", s.mechs)
        self.assertFailed(s.start(b""))

    @spec("RFC 4422", "5", "MUST", "no additional data with the success outcome")
    def test_no_additional_data_on_success(self):
        r = self.ext_server().start(b"")
        self.assertOk(r)
        self.assertFalse(r.out)

    @spec("RFC 4422", "5", "MUST",
          "without an initial response, the server sends an empty challenge")
    def test_no_initial_response(self):
        s = self.ext_server()
        r = s.start(None)
        self.assertContinue(r)
        self.assertEqual(r.out or b"", b"")
        r = s.step(b"")
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")

    @spec("RFC 4422", "3.3", "MUST",
          "a step carries the client's response; NULL for an empty one completes")
    def test_null_step_after_empty_challenge(self):
        s = self.ext_server()
        self.assertContinue(s.start(None))
        r = s.step(None)
        self.assertOk(r, "a NULL (empty) response got another challenge")
        self.assertEqual(r.user, b"alice")


class ExternalClient(SaslTestCase):

    def ext_client(self, **kw):
        kw.setdefault("external", EXT_ID)
        c = self.client("EXTERNAL", **kw)
        if c.first.name == "SASL_NOMECH":
            self.skipTest("EXTERNAL not available")
        return c

    @spec("RFC 4422", "A.1", "ABNF", "without an authzid the message is empty")
    def test_empty_authzid(self):
        c = self.ext_client()
        self.assertOk(c.first)
        self.assertEqual(c.first.mech, "EXTERNAL")
        self.assertEqual(c.first.out, b"")

    @spec("RFC 4422", "A.1", "ABNF", "the message is the authzid, with no NUL")
    def test_authzid_sent(self):
        c = self.ext_client(authzid="bob")
        self.assertOk(c.first)
        self.assertEqual(c.first.out, b"bob")

    @spec("RFC 4422", "A.1", "MUST",
          "there are no additional challenges; a non-empty challenge fails")
    def test_nonempty_challenge_rejected(self):
        c = self.ext_client(no_initial_response=True)
        self.assertContinue(c.first)
        self.assertFailed(c.step(b"unexpected"))

    @spec("RFC 4422", "A.1", "MUST",
          "EXTERNAL is not chosen without external authentication")
    def test_unavailable_without_external_identity(self):
        c = self.client("EXTERNAL")
        self.assertFailed(c.first)

    @spec("RFC 4422", "3.6", "MUST",
          "data after the exchange is complete is a protocol error")
    def test_data_after_success_rejected(self):
        c = self.ext_client()
        self.assertOk(c.first)
        self.assertFailed(c.step(b"more"))
