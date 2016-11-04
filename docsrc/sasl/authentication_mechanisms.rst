.. _authentication_mechanisms:

Authentication Mechanisms
=========================

EXTERNAL
--------

.. todo::
   Content needed here

ANONYMOUS
---------

.. todo::
   Content needed here

PLAIN
-----

.. todo::
   Content needed here

LOGIN
-----

.. todo::
   Content needed here

CRAM-MD5
--------

.. todo::
   Content needed here

DIGEST-MD5
----------

.. todo::
   Content needed here

SCRAM-SHA-1
-----------

.. todo::
   Content needed here

GSSAPI
------

Not sure how to get GSSAPI going? Check out our :ref:`GSSAPI configuration guide <gssapi>`.

.. todo::
   Content needed here

GS2-KRB5
--------

.. todo::
   Content needed here

GS2-IAKERB
----------

.. todo::
   Content needed here

NTLM
----

.. todo::
   Content needed here

SRP
---

.. todo::
   Content needed here

PSSDSS
------

.. todo::
   Content needed here

OTP
---

.. todo::
   Content needed here

Non-SASL Authentication
-----------------------

.. todo::
   Content needed here

This table shows what security flags and features are supported by each
of the mechanisms provided by the Cyrus SASL Library.

+-------------+---------+----------------------------------------------------------------+---------------------------------------------+
|             |         | Security Properties                                            | Features                                    |
+-------------+         +----------------------------------------------------------------+---------------------------------------------+
|             | MAX SSF | NOPLAIN | NOACTIVE | NODICT | FORWARD | NOANON | CRED | MUTUAL | CLT FIRST | SRV FIRST    | SRV LAST | PROXY |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| ANONYMOUS   | 0       | X       |          |        |         |        |      |        | X         |              |          |       |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| CRAM-MD5    | 0       | X       |          |        |         | X      |      |        |           | X            |          |       |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| DIGEST-MD5  | 128     | X       |          |        |         | X      |      | X      | reauth    | initial auth | X        | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| EXTERNAL    | 0       | X       |          | X      |         | X      |      |        | X         |              |          | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| GSSAPI      | 56      | X       | X        |        |         | X      |      | X      | X         |              |          | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| KERBEROS_V4 | 56      | X       | X        |        |         | X      |      | X      |           | X            |          | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| LOGIN       | 0       |         |          |        |         | X      |      |        |           | X            |          |       |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| NTLM        | 0       | X       |          |        |         | X      |      |        | X         |              |          |       |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| OTP         | 0       | X       |          |        | X       | X      |      |        | X         |              |          | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| PLAIN       | 0       |         |          |        |         | X      |      |        | X         |              |          | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+
| SRP         | 128     | X       | X        | X      | X       | X      |      | X      | X         |              | X        | X     |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+

Understanding this table:

Security Properties:

* **MAX SSF** - The maximum Security Strength Factor supported by the mechanism (roughly the number of bits of encryption provided, but may have other meanings, for example an SSF of 1 indicates integrity protection only, no encryption).
* **NOPLAIN** - Mechanism is not susceptable to simple passive (eavesdropping) attack.
* **NOACTIVE** - Protection from active (non-dictionary) attacks during authentication exchange. (Implies MUTUAL).
* **NODICT** - Not susceptable to passive dictionary attack.
* **NOFORWARD** - Breaking one session won't help break the next.
* **NOANON** - Don't permit anonymous logins.
* **CRED** - Mechanism can pass client credentials.
* **MUTUAL** - Supports mutual authentication (authenticates the server to the client)

Features:

* **CLTFIRST** - The client should send first in this mechanism.
* **SRVFIRST** - The server must send first in this mechanism.
* **SRVLAST** - This mechanism supports server-send-last configurations.
* **PROXY** - This mechanism supports proxy authentication.

.. toctree::
    :hidden:

    gssapi
