# SASL wire-level conformance tests

These tests check Cyrus SASL mechanisms against their RFCs by playing one
side of an exchange with exact bytes while libsasl plays the other.

They need only Python 3 (standard library) and the two drivers built in
`tests/`. No sasldb backend, KDC, or network access is required.

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

## How it works

- `tests/t_srv` runs one server-side authentication; `tests/t_cli` runs
  one client-side authentication. Each reads one SASL message per line
  (hex, `-` for no data, or an empty line for zero-length data) and prints
  one JSON result per libsasl call. See `tests/t_wire.h`.
- `t_srv` serves passwords from an in-memory auxprop plugin (`-U user:pass`),
  so tests don't depend on how the library was configured.
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
