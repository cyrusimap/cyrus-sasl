# SASL wire-level conformance tests

These tests check Cyrus SASL mechanisms against their RFCs by playing one
side of an exchange with exact bytes while libsasl plays the other.

Most tests need only Python 3 (standard library) and the two drivers built
in `tests/`. No sasldb backend or network access is required.

The GSSAPI and GS2 tests also need the MIT Kerberos KDC tools (`krb5kdc`,
`kdb5_util`, `kadmin.local`) and the Python `gssapi` module; they're
skipped if either is missing. They start a throwaway KDC on a free
localhost port with its own configuration (`krb5env.py`), so they don't
need root, DNS, `socket_wrapper` or `nss_wrapper`. Set `T_KEEP_KRB5=1` to
keep its directory, with the KDC log, after the run.

## Running

```sh
make check                      # runs these tests, then tests/runtests.py
make -C tests check-conformance # runs only these tests
```

To run the suite directly against a build tree:

```sh
T_BUILDDIR=$PWD/tests T_PLUGINDIR=$PWD/plugins/.libs \
    python3 tests/conformance/run.py -v [-k NAME]
```

The run prints a summary by spec and lists the known bugs still present.
It fails on any test failure, error, or unexpected pass.

### With sanitizers

Memory errors such as a one-byte over-read usually don't change what the
library returns, so the tests can't see them in a normal build. Build with
AddressSanitizer and UndefinedBehaviorSanitizer to catch them:

```sh
./configure --enable-sanitizers
make
make -C tests check-conformance
```

Any sanitizer report from a driver then fails the test that triggered it,
including reports printed after the last response (for example during
cleanup). If your compiler lacks one of the runtimes, pick a subset, for
example `--enable-sanitizers=address`.

Leak detection is off by default because the library has known leaks at
exit. Run with `ASAN_OPTIONS=detect_leaks=1` to see them.

Tests for bugs that only a sanitizer can observe use
`@known_bug(..., only_if=SANITIZED)`, so they're expected failures in
sanitizer builds and ordinary tests otherwise.

## How it works

- `tests/t_srv` runs one server-side authentication; `tests/t_cli` runs
  one client-side authentication. Each reads one SASL message per line
  (hex, `-` for no data, or an empty line for zero-length data) and prints
  one JSON result per libsasl call. See `tests/t_wire.h`.
- `t_srv` serves passwords (`-U user:pass`) and stored secrets such as
  SCRAM's `authPassword` values (`-P user:secret`) from an in-memory auxprop
  plugin, so tests don't depend on how the library was configured.
- After authentication, `E:<hex>` and `D:<hex>` lines run `sasl_encode()`
  and `sasl_decode()`, so tests can send, replay and inspect
  security-layer packets.
- `sasltest.py` wraps the drivers and computes SCRAM values independently
  of the library, so a passing exchange shows agreement with the RFC
  rather than with the library itself.

## Writing tests

Tag each test with the requirement it checks:

```python
@spec("RFC 5802", "5.1", "MUST", "unknown optional extensions MUST be ignored")
```

When a test documents a bug that isn't fixed yet, mark it with the finding's
ID from the conformance audit:

```python
@known_bug("I1", "off-by-one drops the last ServerSignature character")
```

The test then runs as an expected failure. When the bug is fixed, the run
reports it under "Known bugs that now PASS" and fails, so the marker gets
removed and the test becomes a regression guard.

Before adding a `known_bug` marker, confirm that the test fails for the
reason the marker states, not because of a mistake in the test.
