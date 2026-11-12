"""SCRAM (RFC 5802, RFC 7677) wire-level conformance tests.

The Python side computes every SCRAM value independently (sasltest.Scram),
so a passing exchange shows the library agrees with the RFC construction,
not just with itself.

Server tests run against SCRAM-SHA-256 (RFC 7677).  The mechanism-variant
tests check that every SCRAM variant the build offers completes a correct
exchange.
"""

import os

from sasltest import (SCRAM_HASHES, SaslTestCase, Scram, b64, known_bug,
                      parse_attrs, scram_escape, spec, unb64)

MECH = "SCRAM-SHA-256"
USER = "alice"
PASSWORD = "pencil"
USERS = {USER: PASSWORD, "bob": "hunter2"}
CB_NAME = "tls-exporter"
CB_DATA = bytes(range(32))


def new_nonce():
    return b64(os.urandom(18))


class ScramPeer:
    """Plays the client side of SCRAM against the library's server.

    Builds each message from parts so tests can corrupt one field at a time.
    """

    def __init__(self, server, mech=MECH, user=USER, password=PASSWORD,
                 gs2_header="n,,", cbind_data=b"", cnonce=None):
        self.server = server
        self.mech = mech
        self.scram = Scram(mech, password)
        self.user = user
        self.gs2_header = gs2_header
        self.cbind_data = cbind_data
        self.cnonce = cnonce if cnonce is not None else new_nonce()

    def client_first_bare(self):
        return "n=%s,r=%s" % (scram_escape(self.user), self.cnonce)

    def first(self, client_first=None):
        """Send client-first; return the server's Result."""
        if client_first is None:
            client_first = self.gs2_header + self.client_first_bare()
        self.sent_first = client_first
        r = self.server.start(client_first.encode("utf-8"))
        if r.cont:
            self.server_first = r.out.decode("utf-8")
            attrs = dict(parse_attrs(self.server_first))
            self.nonce = attrs["r"]
            self.salt = unb64(attrs["s"])
            self.iterations = int(attrs["i"])
        return r

    def final(self, channel_binding=None, nonce=None, proof=None,
              extra="", password_scram=None):
        """Send client-final; return the server's Result.

        Any argument overrides the correct value, to send a bad message.
        """
        cb = channel_binding
        if cb is None:
            cb = b64(self.gs2_header.encode("utf-8") + self.cbind_data)
        nonce = self.nonce if nonce is None else nonce
        without_proof = "c=%s,r=%s" % (cb, nonce)
        bare = self.sent_first[len(self.gs2_header):]
        self.auth_message = ",".join(
            (bare, self.server_first, without_proof)).encode("utf-8")
        scram = password_scram or self.scram
        if proof is None:
            proof = scram.client_proof(self.salt, self.iterations,
                                       self.auth_message)
        message = without_proof + ",p=" + b64(proof) + extra
        return self.server.step(message.encode("utf-8"))

    def expected_verifier(self):
        return "v=" + b64(self.scram.server_signature(
            self.salt, self.iterations, self.auth_message))


class SuccessDataMixin:
    """Run servers as for a protocol that carries data with success."""

    def server(self, mech, **kw):
        kw.setdefault("success_data", True)
        return super().server(mech, **kw)


class ScramServer(SuccessDataMixin, SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech(MECH)

    def peer(self, server=None, **kw):
        return ScramPeer(server or self.server(MECH, users=USERS), **kw)

    # --- a correct exchange ---

    @spec("RFC 5802", "3", "MUST", "server accepts a correct ClientProof")
    @spec("RFC 7677", "3", "MUST", "SCRAM-SHA-256 uses SHA-256 throughout")
    def test_valid_exchange(self):
        p = self.peer()
        self.assertContinue(p.first())
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.user, USER.encode())

    @spec("RFC 5802", "5.1", "MUST", "server-final carries v=ServerSignature")
    def test_server_signature(self):
        p = self.peer()
        p.first()
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.out.decode(), p.expected_verifier())

    @spec("RFC 4422", "5", "MUST",
          "without success data, the server sends v= as a final challenge")
    def test_server_final_as_challenge(self):
        p = self.peer(self.server(MECH, users=USERS, success_data=False))
        p.first()
        r = p.final()
        self.assertContinue(r)
        self.assertEqual(r.out.decode(), p.expected_verifier())
        r = p.server.step(b"")
        self.assertOk(r)
        self.assertFalse(r.out)

    @spec("RFC 5802", "5.1", "MUST",
          "the server nonce starts with the client nonce and extends it")
    def test_server_nonce_extends_client_nonce(self):
        p = self.peer()
        p.first()
        self.assertTrue(p.nonce.startswith(p.cnonce))
        self.assertGreater(len(p.nonce), len(p.cnonce))

    @spec("RFC 5802", "7", "ABNF", "server-first is r=,s=,i= in that order")
    def test_server_first_syntax(self):
        p = self.peer()
        p.first()
        self.assertEqual([a for a, _ in parse_attrs(p.server_first)][:3],
                         ["r", "s", "i"])
        self.assertTrue(p.salt)

    @spec("RFC 7677", "4", "SHOULD",
          "the server announces an iteration count of at least 4096")
    def test_default_iteration_count(self):
        p = self.peer()
        p.first()
        self.assertGreaterEqual(p.iterations, 4096)

    @known_bug("I3", "server announces the configured iteration count unchecked")
    @spec("RFC 5802", "7", "ABNF", 'iteration-count = "i=" posit-number')
    def test_iteration_count_never_zero(self):
        server = self.server(MECH, users=USERS,
                             opts={"scram_iteration_counter": "0"})
        p = self.peer(server)
        p.first()
        self.assertGreater(p.iterations, 0)

    # --- authentication failures ---

    @spec("RFC 5802", "3", "MUST", "server rejects a ClientProof for the wrong password")
    def test_wrong_password(self):
        p = self.peer()
        p.first()
        self.assertFailed(p.final(password_scram=Scram(MECH, "wrong")))

    @spec("RFC 5802", "3", "MUST", "server rejects a corrupted ClientProof")
    def test_corrupted_proof(self):
        p = self.peer()
        p.first()
        good = p.scram.client_proof(p.salt, p.iterations, b"")  # right length
        self.assertFailed(p.final(proof=bytes(b ^ 1 for b in good)))

    @spec("RFC 5802", "5.1", "MUST", "client-final nonce must equal the combined nonce")
    def test_nonce_mismatch(self):
        p = self.peer()
        p.first()
        self.assertFailed(p.final(nonce=p.nonce + "x"))

    @spec("RFC 5802", "5.1", "MUST", "unknown user fails")
    def test_unknown_user(self):
        p = self.peer(user="mallory")
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    # --- client-first syntax ---

    @spec("RFC 5802", "5.1", "MUST", "server fails on a mandatory extension (m=)")
    def test_mandatory_extension_rejected(self):
        p = self.peer()
        self.assertFailed(p.first("n,,m=ext,n=alice,r=" + p.cnonce))

    @spec("RFC 5802", "5.1", "MUST",
          "'=' in saslname not followed by 2C or 3D fails")
    def test_invalid_username_escape(self):
        p = self.peer()
        self.assertFailed(p.first("n,,n=al=41ice,r=" + p.cnonce))

    @spec("RFC 5802", "7", "ABNF", "gs2-cbind-flag is p=, n or y")
    def test_unknown_gs2_flag(self):
        p = self.peer()
        self.assertFailed(p.first("x,,n=alice,r=" + p.cnonce))

    @spec("RFC 5802", "7", "ABNF", "authzid with no terminating client-first fields")
    def test_truncated_after_authzid(self):
        # Also exercises finding H1 (one-byte over-read); detecting the
        # over-read itself needs a build with AddressSanitizer.
        p = self.peer()
        self.assertFailed(p.first("n,a=abcdef,"))

    @known_bug("H4", "a=, (empty authzid) is accepted as no authzid")
    @spec("RFC 5802", "7", "ABNF", "authzid = \"a=\" saslname, saslname = 1*(...)")
    def test_empty_authzid_rejected(self):
        p = self.peer(gs2_header="n,a=,")
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @known_bug("H4", "non-printable client nonce is accepted")
    @spec("RFC 5802", "7", "ABNF", "c-nonce = printable (%x21-2B / %x2D-7E)")
    def test_nonprintable_nonce_rejected(self):
        p = self.peer(cnonce="abc\x01def")
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @spec("RFC 4422", "5", "MUST",
          "without an initial response, the server sends an empty challenge")
    def test_no_initial_response(self):
        server = self.server(MECH, users=USERS)
        r = server.start(None)
        self.assertContinue(r)
        self.assertEqual(r.out or b"", b"")

    # --- client-final syntax ---

    @spec("RFC 5802", "7", "ABNF", "proof is the last attribute of client-final")
    def test_data_after_proof_rejected(self):
        p = self.peer()
        p.first()
        self.assertFailed(p.final(extra=",x=1"))

    # --- authorization identity ---

    @spec("RFC 5802", "5.1", "MUST", "a= equal to the username is accepted")
    def test_authzid_same_as_user(self):
        p = self.peer(gs2_header="n,a=alice,")
        p.first()
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.user, b"alice")

    @spec("RFC 5802", "5.1", "MUST", "a= requires authorization to act as that identity")
    def test_authzid_not_permitted(self):
        p = self.peer(gs2_header="n,a=bob,")
        p.first()
        self.assertFailed(p.final())

    @spec("RFC 5802", "5.1", "MUST", "a= is honored when authorized")
    def test_authzid_permitted(self):
        server = self.server(MECH, users=USERS, proxies=[("alice", "bob")])
        p = self.peer(server, gs2_header="n,a=bob,")
        p.first()
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.user, b"bob")
        self.assertEqual(r.authuser, b"alice")

    @spec("RFC 5802", "5.1", "MUST", "a= values are unescaped (=2C, =3D)")
    def test_authzid_escaping(self):
        server = self.server(MECH, users=USERS, proxies=[("alice", "b,o=b")])
        p = self.peer(server, gs2_header="n,a=b=2Co=3Db,")
        p.first()
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.user, b"b,o=b")


class ScramServerChannelBinding(SuccessDataMixin, SaslTestCase):

    def setUp(self):
        super().setUp()
        self.require_mech(MECH)

    def cb_server(self, mech=MECH + "-PLUS", critical=False, data=CB_DATA):
        return self.server(mech, users=USERS, cbinding=(CB_NAME, data),
                           critical=critical)

    @spec("RFC 5802", "6", "MUST", "server with channel binding offers the -PLUS variant")
    def test_plus_advertised(self):
        s = self.cb_server()
        self.assertIn(MECH + "-PLUS", s.mechs)
        self.assertIn(MECH, s.mechs)

    @spec("RFC 5801", "5", "MUST",
          "when binding is required, only the -PLUS variant is advertised")
    def test_only_plus_when_critical(self):
        s = self.cb_server(critical=True)
        self.assertIn(MECH + "-PLUS", s.mechs)
        self.assertNotIn(MECH, s.mechs)

    @spec("RFC 5802", "6", "MUST", "p= with the correct binding data succeeds")
    def test_p_matching_binding(self):
        p = ScramPeer(self.cb_server(), mech=MECH + "-PLUS",
                      gs2_header="p=%s,," % CB_NAME, cbind_data=CB_DATA)
        self.assertContinue(p.first())
        self.assertOk(p.final())

    @spec("RFC 5802", "6", "MUST", "server MUST validate c= against its own binding data")
    def test_p_mismatched_binding(self):
        p = ScramPeer(self.cb_server(), mech=MECH + "-PLUS",
                      gs2_header="p=%s,," % CB_NAME, cbind_data=b"\xff" * 32)
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @spec("RFC 5802", "6", "MUST", "p= fails when the server has no binding data")
    def test_p_without_server_binding(self):
        server = self.server(MECH, users=USERS)
        p = ScramPeer(server, gs2_header="p=%s,," % CB_NAME, cbind_data=CB_DATA)
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @spec("RFC 5802", "6", "MUST",
          "server MUST fail if the client sent y and the server supports binding")
    def test_y_downgrade_detected(self):
        p = ScramPeer(self.cb_server(mech=MECH), gs2_header="y,,")
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @spec("RFC 5802", "6", "MUST", "y is accepted when the server has no binding")
    def test_y_without_server_binding(self):
        p = ScramPeer(self.server(MECH, users=USERS), gs2_header="y,,")
        p.first()
        self.assertOk(p.final())

    @spec("RFC 5801", "5", "MUST", "n is rejected when binding is required")
    def test_n_rejected_when_critical(self):
        p = ScramPeer(self.cb_server(mech=MECH + "-PLUS", critical=True))
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)

    @spec("RFC 5802", "6", "MUST", "c= must exactly match the gs2 header sent")
    def test_c_header_mismatch(self):
        p = ScramPeer(self.server(MECH, users=USERS))
        p.first()
        self.assertFailed(p.final(channel_binding=b64(b"y,,")))

    @known_bug("H2", "trailing cbind-data is accepted after n or y")
    @spec("RFC 5802", "7", "MUST", "cbind-data MUST be absent for y or n")
    def test_c_trailing_data_with_n(self):
        p = ScramPeer(self.server(MECH, users=USERS))
        p.first()
        self.assertFailed(p.final(channel_binding=b64(b"n,,JUNK")))

    @known_bug("I6", "server ignores whether the -PLUS name was selected")
    @spec("RFC 5802", "6", "MUST",
          "the -PLUS variant is the channel-binding variant; n under -PLUS is inconsistent")
    def test_n_under_plus_name(self):
        p = ScramPeer(self.cb_server(mech=MECH + "-PLUS"), mech=MECH + "-PLUS")
        r = p.first()
        if r.cont:
            r = p.final()
        self.assertFailed(r)


class ScramVariants(SuccessDataMixin, SaslTestCase):
    """Every SCRAM variant the build offers completes a correct exchange."""

    def run_variant(self, mech):
        server = self.server(mech, users=USERS)
        if mech not in server.mechs:
            self.skipTest("%s not available in this build" % mech)
        p = ScramPeer(server, mech=mech)
        self.assertContinue(p.first())
        r = p.final()
        self.assertOk(r)
        self.assertEqual(r.out.decode(), p.expected_verifier())

    @spec("RFC 5802", "5", "MUST", "SCRAM-SHA-1 exchange matches RFC 5802")
    def test_sha1(self):
        self.run_variant("SCRAM-SHA-1")

    @spec("RFC 7677", "3", "MUST", "SCRAM-SHA-256 exchange matches RFC 7677")
    def test_sha256(self):
        self.run_variant("SCRAM-SHA-256")

    @spec("RFC 5802", "5", "INTEROP", "SCRAM-SHA-224 follows the RFC 5802 construction")
    def test_sha224(self):
        self.run_variant("SCRAM-SHA-224")

    @spec("RFC 5802", "5", "INTEROP", "SCRAM-SHA-384 follows the RFC 5802 construction")
    def test_sha384(self):
        self.run_variant("SCRAM-SHA-384")

    @spec("RFC 5802", "5", "INTEROP", "SCRAM-SHA-512 follows the RFC 5802 construction")
    def test_sha512(self):
        self.run_variant("SCRAM-SHA-512")


class ScramClient(SaslTestCase):
    """The Python side plays the server; the library is the client."""

    def setUp(self):
        super().setUp()
        self.require_mech(MECH)

    def start(self, mechlist=MECH, **kw):
        kw.setdefault("authname", USER)
        kw.setdefault("password", PASSWORD)
        c = self.client(mechlist, **kw)
        self.assertContinue(c.first)
        self.client_first = c.first.out.decode("utf-8")
        flag_end = self.client_first.index(",")
        authz_end = self.client_first.index(",", flag_end + 1)
        self.gs2_header = self.client_first[:authz_end + 1]
        self.bare = self.client_first[authz_end + 1:]
        self.cnonce = dict(parse_attrs(self.bare))["r"]
        return c

    def server_first(self, c, nonce=None, salt=b"saltsaltsalt", iterations=4096,
                     extra=""):
        self.nonce = nonce if nonce is not None else self.cnonce + new_nonce()
        self.salt, self.iterations = salt, iterations
        self.sfirst = "r=%s,s=%s,i=%d%s" % (self.nonce, b64(salt), iterations, extra)
        return c.step(self.sfirst.encode("utf-8"))

    def check_final(self, result, mech=MECH, cbind_data=b""):
        """Verify the client-final message and return the AuthMessage."""
        attrs = parse_attrs(result.out)
        names = [a for a, _ in attrs]
        self.assertEqual(names[0], "c")
        self.assertEqual(names[-1], "p")
        values = dict(attrs)
        self.assertEqual(unb64(values["c"]),
                         self.gs2_header.encode() + cbind_data)
        self.assertEqual(values["r"], self.nonce)
        without_proof = result.out.decode()[:result.out.decode().rindex(",p=")]
        auth = ",".join((self.bare, self.sfirst, without_proof)).encode()
        scram = Scram(mech, PASSWORD)
        expected = scram.client_proof(self.salt, self.iterations, auth)
        self.assertEqual(unb64(values["p"]), expected, "ClientProof mismatch")
        return scram, auth

    def verifier(self, scram, auth):
        return "v=" + b64(scram.server_signature(self.salt, self.iterations, auth))

    # --- message construction ---

    @spec("RFC 5802", "7", "ABNF", "client-first is gs2-header n=user,r=nonce")
    def test_client_first_syntax(self):
        self.start()
        self.assertEqual(self.gs2_header, "n,,")
        self.assertEqual([a for a, _ in parse_attrs(self.bare)], ["n", "r"])
        self.assertEqual(dict(parse_attrs(self.bare))["n"], USER)

    @spec("RFC 5802", "7", "ABNF", "c-nonce = printable, no comma")
    def test_client_nonce_printable(self):
        self.start()
        self.assertTrue(self.cnonce)
        for ch in self.cnonce:
            self.assertTrue(0x21 <= ord(ch) <= 0x7e and ch != ",",
                            "non-printable nonce character %r" % ch)

    @spec("RFC 5802", "5.1", "MUST", "username escapes ',' as =2C and '=' as =3D")
    def test_username_escaping(self):
        self.start(authname="a,b=c")
        self.assertEqual(dict(parse_attrs(self.bare))["n"], "a=2Cb=3Dc")

    @spec("RFC 5802", "5.1", "MUST", "authzid is sent as a= in the gs2 header")
    def test_authzid_in_header(self):
        self.start(authzid="admin")
        self.assertEqual(self.gs2_header, "n,a=admin,")

    @spec("RFC 5802", "3", "MUST", "client computes the RFC 5802 ClientProof")
    def test_client_proof(self):
        c = self.start()
        r = self.server_first(c)
        self.assertContinue(r)
        self.check_final(r)

    # --- mutual authentication ---

    @spec("RFC 5802", "5.1", "MUST", "client succeeds on a correct ServerSignature")
    def test_valid_exchange(self):
        c = self.start()
        r = self.server_first(c)
        scram, auth = self.check_final(r)
        self.assertOk(c.step(self.verifier(scram, auth).encode()))

    @spec("RFC 5802", "5.1", "MUST", "client MUST verify ServerSignature")
    def test_bad_server_signature(self):
        c = self.start()
        r = self.server_first(c)
        self.check_final(r)
        self.assertFailed(c.step(("v=" + b64(b"\0" * 32)).encode()))

    @spec("RFC 5802", "5.1", "MUST", "client fails on a server-error (e=)")
    def test_server_error(self):
        c = self.start()
        self.server_first(c)
        self.assertFailed(c.step(b"e=other-error"))

    @spec("RFC 5802", "5.1", "MUST", "client fails when the server nonce doesn't extend its own")
    def test_server_nonce_not_prefixed(self):
        c = self.start()
        self.assertFailed(self.server_first(c, nonce=new_nonce() + new_nonce()))

    @spec("RFC 5802", "5.1", "MUST", "client fails on a mandatory extension (m=)")
    def test_mandatory_extension(self):
        c = self.start()
        nonce = self.cnonce + new_nonce()
        r = c.step(("m=ext,r=%s,s=%s,i=4096" % (nonce, b64(b"salt"))).encode())
        self.assertFailed(r)

    @known_bug("I1", "off-by-one drops the last ServerSignature character")
    @spec("RFC 5802", "5.1", "MUST", "unknown optional extensions MUST be ignored")
    def test_server_final_extension_ignored(self):
        c = self.start()
        r = self.server_first(c)
        scram, auth = self.check_final(r)
        self.assertOk(c.step((self.verifier(scram, auth) + ",x=1").encode()))

    @known_bug("I3", "client rejects iteration counts above 65536")
    @spec("RFC 5802", "5.1", "INTEROP", "client accepts a large iteration count")
    def test_large_iteration_count(self):
        c = self.start()
        r = self.server_first(c, iterations=100000)
        self.assertContinue(r)
        scram, auth = self.check_final(r)
        self.assertOk(c.step(self.verifier(scram, auth).encode()))

    @spec("RFC 4422", "3.6", "MUST",
          "data after the exchange is complete is a protocol error")
    def test_data_after_success(self):
        c = self.start()
        r = self.server_first(c)
        scram, auth = self.check_final(r)
        self.assertOk(c.step(self.verifier(scram, auth).encode()))
        self.assertFailed(c.step(b"more"))

    # --- channel binding ---

    @spec("RFC 5802", "6", "MUST", "client with binding data picks -PLUS and sends p=")
    def test_selects_plus(self):
        mech = MECH + "-PLUS"
        c = self.start("%s %s" % (MECH, mech), cbinding=(CB_NAME, CB_DATA))
        self.assertEqual(self.gs2_header, "p=%s,," % CB_NAME)
        r = self.server_first(c)
        scram, auth = self.check_final(r, mech=mech, cbind_data=CB_DATA)
        self.assertOk(c.step(self.verifier(scram, auth).encode()))

    @known_bug("I6", "client reports the non-PLUS name while using channel binding")
    @spec("RFC 5801", "5", "MUST",
          "client MUST use p with the PLUS variant, and so names that variant")
    def test_plus_name_reported(self):
        c = self.start("%s %s-PLUS" % (MECH, MECH), cbinding=(CB_NAME, CB_DATA))
        self.assertEqual(self.gs2_header, "p=%s,," % CB_NAME)
        self.assertEqual(c.first.mech, MECH + "-PLUS")

    @spec("RFC 5802", "6", "MUST",
          "client with binding data sends y when the server offers no -PLUS")
    def test_y_when_no_plus_offered(self):
        self.start("%s SCRAM-SHA-1" % MECH, cbinding=(CB_NAME, CB_DATA))
        self.assertEqual(self.gs2_header, "y,,")

    @known_bug("S7", "client sends n instead of y when only one mechanism is listed")
    @spec("RFC 5801", "5", "MUST NOT",
          "client that supports binding MUST NOT send n when the server appears not to")
    def test_y_with_single_mechanism(self):
        self.start(MECH, cbinding=(CB_NAME, CB_DATA))
        self.assertEqual(self.gs2_header, "y,,")

    @spec("RFC 5802", "6", "MUST", "client without binding data sends n")
    def test_n_without_binding(self):
        self.start("%s %s-PLUS" % (MECH, MECH))
        self.assertEqual(self.gs2_header, "n,,")
