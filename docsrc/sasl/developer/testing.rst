.. _testing:

=======
Testing
=======

.. note::

    This document is mainly useful for people doing libsasl development
    or users having a lot of difficulty getting libsasl to work.

Testing the CMU SASL Library with the included sample applications
==================================================================

The CMU SASL library comes with two small sample programs:
sample-client and sample-server.  Each of these programs dump base-64
SASL iterations to STDOUT, and read the next iteration from STDIN.
Lines preceded by "C: " are from the client, and from "S: " are from
the server.

This makes it fairly straightforward to test mechanisms; simply run
the sample-client on the "client" machine, and sample-server on the
"server" machine.

Both programs take a -m MECH command line argument; this can be used
to force the mechanism used in the exchange.  GSSAPI requires
that the IP addresses of both client and server be set, along with the
service name, and the server's fully-qualified hostname; these are
done through more command line arguments.

Example
-------

Here's the client side of an exchange.  The mechanism selection code
chooses GSSAPI; negotiation takes place, and the client is
authenticated.  This is being run on the machine SPOOKY.ANDREW.CMU.EDU
(128.2.121.162), pretending to be talking to an "rcmd" service running
on port 23 (note the semicolons in the IP address.  There is a strong
chance these will need to be escaped for proper interpretation by the shell):

::

    > ./sample-client -i local=128.2.121.162;23,remote=128.2.121.162;23 -s rcmd -n SPOOKY.ANDREW.CMU.EDU
    Waiting for mechanism list from server...
    S: UExBSU4gQU5PTllNT1VTIEtFUkJFUk9TX1Y0IERJR0VTVC1NRDUgQ1JBTS1NRDUgAAAAAED5EEA=
    Choosing best mechanism from: PLAIN ANONYMOUS GSSAPI CRAM-MD5
    Using mechanism GSSAPI
    Preparing initial.
    Sending initial response...
    C: S0VSQkVST1NfVjQA
    Waiting for server reply...
    S: hVQFjA==
    Sending response...
    C: BAYCQU5EUkVXLkNNVS5FRFUAOCDnIsZLQRdjLHXvzPNgpURYVj1iMqBIcTRaMpEQ8vWeYnfB+mTCVEa2URpkVgpzS1161MAX7ERzFV/EfGKlrAhGJCdN56mQ3eL2PzJlK7Z9ctKv4gKErcmV
    Waiting for server reply...
    S: BgcvFb63CLs=
    Sending response...
    C: ohBT+Jqab9zmDzclN7GSTw==
    Negotiation complete
    >


Here's the server side of the same dialog:

::

    > ./sample-server -s rcmd -i local=128.2.121.162;23,remote=128.2.121.162;23
    Generating client mechanism list...
    Sending list of 5 mechanism(s)
    S: UExBSU4gQU5PTllNT1VTIEtFUkJFUk9TX1Y0IERJR0VTVC1NRDUgQ1JBTS1NRDUgAAAAAED5EEA=
    Waiting for client mechanism...
    C: S0VSQkVST1NfVjQA
    Sending response...
    S: hVQFjA==
    Waiting for client reply...
    C: BAYCQU5EUkVXLkNNVS5FRFUAOCDnIsZLQRdjLHXvzPNgpURYVj1iMqBIcTRaMpEQ8vWeYnfB+mTCVEa2URpkVgpzS1161MAX7ERzFV/EfGKlrAhGJCdN56mQ3eL2PzJlK7Z9ctKv4gKErcmV
    Sending response...
    S: BgcvFb63CLs=
    Waiting for client reply...
    C: ohBT+Jqab9zmDzclN7GSTw==
    Negotiation complete
    Username: rob
    Realm: ANDREW.CMU.EDU
    SSF: 56
    >


Running the Testsuite application
=================================

The Testsuite application in the utils directory tries out all the
functionality of libsasl against itself. When you run the application
it displays some requirements for running, such as being able to read
and write to the sasldb file. If this program is set up correctly and
still fails we'd like to hear about it at cyrus-bugs@andrew.cmu.edu.


Cryptographic callback tests
============================

``tests/t_crypto`` checks callback selection, connection isolation, buffer
bounds, error propagation, and erasure of failed outputs. It works with both
built-in and callback-only builds. ``tests/t_scram`` checks the calculations
in RFC 5802 and RFC 7677, client/server exchanges, channel binding, backend
failures, bounded iteration counts, interleaved connections, and
interoperability with the built-in implementation, including verifiers
created with ``sasl_setpass()``. These tests require
no network service or password database. The SCRAM test is skipped
when no cryptographic test backend is available in a callback-only build.

After building, run the focused tests with::

    make -C tests check-TESTS TESTS="t_crypto t_scram t_scram_global.sh"

The full ``make check`` also runs the existing integration tests and needs
their external dependencies.
