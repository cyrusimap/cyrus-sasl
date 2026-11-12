"""Harness for the Cyrus SASL wire-level conformance tests.

Each test starts one of the C drivers (tests/t_srv or tests/t_cli) as a
subprocess and plays the other side of a SASL exchange with exact bytes.
The drivers make one libsasl call per input line and print one JSON object
per call; see tests/t_wire.h for the line protocol.

Only the Python standard library is used.
"""

import base64
import hashlib
import hmac
import json
import os
import select
import subprocess
import unittest

TIMEOUT = 20  # seconds to wait for any single driver response

HERE = os.path.dirname(os.path.abspath(__file__))
BUILDDIR = os.environ.get("T_BUILDDIR") or os.path.dirname(HERE)


# ---------------------------------------------------------------------------
# Spec and known-bug markers
# ---------------------------------------------------------------------------

def spec(ref, section, level, requirement=None):
    """Tag a test with the spec requirement it checks.

    ref:   e.g. "RFC 5802"
    level: MUST, MUST NOT, SHOULD, SHOULD NOT, SHALL, MAY, ABNF, or INTEROP
    """
    def deco(func):
        tags = list(getattr(func, "spec_tags", []))
        tags.append((ref, section, level, requirement))
        func.spec_tags = tags
        return func
    return deco


def known_bug(audit_id, summary):
    """Mark a test that fails because of a known, unfixed bug.

    audit_id refers to the finding on the conformance audit page.  The test
    is an expected failure; once the bug is fixed it will report an
    unexpected success, and this marker should be removed.
    """
    def deco(func):
        func = unittest.expectedFailure(func)
        func.known_bug = (audit_id, summary)
        return func
    return deco


# ---------------------------------------------------------------------------
# Driver processes
# ---------------------------------------------------------------------------

class Result:
    """One libsasl call's outcome, as reported by a driver."""

    def __init__(self, obj):
        self.raw = obj
        self.rc = obj.get("rc")
        self.name = obj.get("name")
        self.out = bytes.fromhex(obj["out"]) if obj.get("out") is not None else None
        self.detail = obj.get("detail")
        self.mech = obj.get("mech")
        self.user = bytes.fromhex(obj["user"]) if obj.get("user") is not None else None
        self.authuser = bytes.fromhex(obj["authuser"]) if obj.get("authuser") is not None else None
        self.ssf = obj.get("ssf")

    @property
    def ok(self):
        return self.name == "SASL_OK"

    @property
    def cont(self):
        return self.name == "SASL_CONTINUE"

    @property
    def failed(self):
        return not (self.ok or self.cont)

    def __repr__(self):
        parts = ["%s" % self.name]
        if self.out is not None:
            parts.append("out=%r" % self.out)
        if self.mech:
            parts.append("mech=%s" % self.mech)
        if self.user is not None:
            parts.append("user=%r" % self.user)
        if self.detail:
            parts.append("detail=%r" % self.detail)
        return "<Result %s>" % " ".join(parts)


class DriverError(Exception):
    pass


class Driver:
    program = None

    def __init__(self, args):
        path = os.path.join(BUILDDIR, self.program)
        if not os.path.exists(path):
            raise DriverError("driver not built: %s" % path)
        env = dict(os.environ)
        self.proc = subprocess.Popen(
            [path] + [str(a) for a in args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env)
        self._buf = b""

    def _readline(self):
        fd = self.proc.stdout.fileno()
        while b"\n" not in self._buf:
            ready, _, _ = select.select([fd], [], [], TIMEOUT)
            if not ready:
                self.close()
                raise DriverError("timed out waiting for %s" % self.program)
            chunk = os.read(fd, 65536)
            if not chunk:
                err = self.proc.stderr.read().decode("utf-8", "replace")
                self.proc.wait()
                raise DriverError("%s exited (status %s): %s"
                                  % (self.program, self.proc.returncode, err.strip()))
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line.decode("ascii"))

    def _send(self, data):
        if data is None:
            line = "-"
        else:
            line = bytes(data).hex()
        try:
            self.proc.stdin.write((line + "\n").encode("ascii"))
            self.proc.stdin.flush()
        except BrokenPipeError:
            raise DriverError("%s is no longer reading input" % self.program)

    def call(self, data):
        """Send one message (bytes, or None for no data) and return the Result."""
        self._send(data)
        return Result(self._readline())

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for f in (self.proc.stdout, self.proc.stderr):
            if f:
                f.close()


def _common_args(opts=None, cbinding=None, critical=False, min_ssf=None,
                 max_ssf=None, maxbuf=None, secflags=None, external=None,
                 external_ssf=None, service=None, fqdn=None,
                 success_data=False):
    args = []
    if success_data:
        args.append("-S")
    for key, value in (opts or {}).items():
        args += ["-o", "%s=%s" % (key, value)]
    if cbinding is not None:
        name, data = cbinding
        args += ["-c", "%s:%s" % (name, bytes(data).hex())]
    if critical:
        args.append("-C")
    for flag, value in (("-n", min_ssf), ("-x", max_ssf), ("-b", maxbuf),
                        ("-f", secflags), ("-e", external),
                        ("-E", external_ssf), ("-s", service), ("-h", fqdn)):
        if value is not None:
            args += [flag, value]
    return args


class Server(Driver):
    """A libsasl server running one authentication with mechanism `mech`.

    users:   {name: password} served by the in-memory password store
    proxies: [(authid, authzid)] pairs allowed to proxy; when given, they
             replace the library's default proxy policy
    success_data: the protocol can carry additional data with the success
             outcome (SASL_SUCCESS_DATA); otherwise the library sends such
             data as a final challenge (RFC 4422 section 5)
    """
    program = "t_srv"

    def __init__(self, mech, users=None, proxies=None, realm=None, **kw):
        args = ["-m", mech]
        for name, password in (users or {}).items():
            args += ["-U", "%s:%s" % (name, password)]
        for authid, authzid in (proxies or []):
            args += ["-A", "%s:%s" % (authid, authzid)]
        if realm is not None:
            args += ["-r", realm]
        args += _common_args(**kw)
        super().__init__(args)
        self.mechs = self._readline()["mechs"].split()

    def start(self, initial):
        """Call sasl_server_start with the client's initial response."""
        return self.call(initial)

    def step(self, response):
        """Call sasl_server_step with the client's response."""
        return self.call(response)


class Client(Driver):
    """A libsasl client.  sasl_client_start runs immediately; its result
    is in .first.

    no_initial_response: start without initial-response support, as for a
    protocol that can't carry one.
    """
    program = "t_cli"

    def __init__(self, mechlist, authname=None, authzid=None, password=None,
                 no_initial_response=False, **kw):
        args = ["-m", mechlist]
        if authname is not None:
            args += ["-u", authname]
        if authzid is not None:
            args += ["-a", authzid]
        if password is not None:
            args += ["-w", password]
        if no_initial_response:
            args.append("-N")
        args += _common_args(**kw)
        super().__init__(args)
        self.first = Result(self._readline())

    def step(self, challenge):
        """Call sasl_client_step with a server challenge (None for no data)."""
        return self.call(challenge)


class SaslTestCase(unittest.TestCase):
    """Base class: tracks drivers so they are always cleaned up."""

    def setUp(self):
        self._drivers = []

    def tearDown(self):
        for d in self._drivers:
            d.close()

    def server(self, mech, **kw):
        s = Server(mech, **kw)
        self._drivers.append(s)
        return s

    def client(self, mechlist, **kw):
        c = Client(mechlist, **kw)
        self._drivers.append(c)
        return c

    def require_mech(self, mech):
        """Skip unless the server advertises `mech` (with a dummy user)."""
        s = self.server(mech, users={"probe": "probe"})
        if mech not in s.mechs:
            self.skipTest("%s not available in this build" % mech)

    def assertOk(self, result, msg=None):
        if not result.ok:
            self.fail(msg or "expected SASL_OK, got %r" % result)

    def assertContinue(self, result, msg=None):
        if not result.cont:
            self.fail(msg or "expected SASL_CONTINUE, got %r" % result)

    def assertFailed(self, result, msg=None):
        if not result.failed:
            self.fail(msg or "expected the exchange to fail, got %r" % result)


# ---------------------------------------------------------------------------
# SCRAM (RFC 5802) calculator, independent of the library under test
# ---------------------------------------------------------------------------

SCRAM_HASHES = {
    "SCRAM-SHA-1": "sha1",
    "SCRAM-SHA-224": "sha224",
    "SCRAM-SHA-256": "sha256",
    "SCRAM-SHA-384": "sha384",
    "SCRAM-SHA-512": "sha512",
}


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text, validate=True)


def scram_escape(name):
    """saslname escaping from RFC 5802 section 5.1."""
    return name.replace("=", "=3D").replace(",", "=2C")


def parse_attrs(message):
    """Split a SCRAM message into an ordered list of (attr, value)."""
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    attrs = []
    for part in message.split(","):
        if len(part) < 2 or part[1] != "=":
            raise ValueError("malformed SCRAM attribute %r in %r" % (part, message))
        attrs.append((part[0], part[2:]))
    return attrs


class Scram:
    """Computes RFC 5802 values for one exchange."""

    def __init__(self, mech, password):
        base = mech[:-5] if mech.endswith("-PLUS") else mech
        self.hash = SCRAM_HASHES[base]
        self.password = password.encode("utf-8")

    def H(self, data):
        return hashlib.new(self.hash, data).digest()

    def HMAC(self, key, data):
        return hmac.new(key, data, self.hash).digest()

    def keys(self, salt, iterations):
        salted = hashlib.pbkdf2_hmac(self.hash, self.password, salt, iterations)
        client_key = self.HMAC(salted, b"Client Key")
        server_key = self.HMAC(salted, b"Server Key")
        return client_key, self.H(client_key), server_key

    def client_proof(self, salt, iterations, auth_message):
        client_key, stored_key, _ = self.keys(salt, iterations)
        signature = self.HMAC(stored_key, auth_message)
        return bytes(a ^ b for a, b in zip(client_key, signature))

    def server_signature(self, salt, iterations, auth_message):
        _, _, server_key = self.keys(salt, iterations)
        return self.HMAC(server_key, auth_message)
