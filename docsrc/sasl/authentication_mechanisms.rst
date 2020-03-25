.. _authentication_mechanisms:

=========================
Authentication Mechanisms
=========================

Mechanisms
==========

ANONYMOUS
---------

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

EXTERNAL
--------

.. todo::
   Content needed here


G2
-----

.. todo::
   Content needed here


GSSAPI
------

Not sure how to get GSSAPI going? Check out our :ref:`GSSAPI configuration guide <gssapi>`.

.. todo::
   Content needed here


GSS-SPEGNO
----------

.. todo::
   Content needed here

KERBEROS_V4
-----------

.. todo::
   Content needed here

LOGIN
-----

.. todo::
   Content needed here

NTLM
----

.. todo::
   Content needed here

OTP
---

  * OTP-MD4
  * OTP-MD5
  * OTP-SHA1

.. todo::
   Content needed here

PASSDSS
-------

  * PASSDSS-3DES-1

.. todo::
   Content needed here

PLAIN
-----

.. todo::
   Content needed here

SCRAM
-----

  * SCRAM-SHA-1(-PLUS)
  * SCRAM-SHA-224(-PLUS)
  * SCRAM-SHA-256(-PLUS)
  * SCRAM-SHA-384(-PLUS)
  * SCRAM-SHA-512(-PLUS)

.. todo::
   Content needed here

SRP
---

  * mda=sha1,rmd160,md5
  * confidentiality=des-ofb,des-ede-ofb,aes-128-ofb,bf-ofb,cast5-ofb,idea-ofb

.. todo::
   Content needed here

Non-SASL Authentication
-----------------------

.. todo::
   Content needed here

----

Summary
=======

This table shows what security flags and features are supported by each
of the mechanisms provided by the Cyrus SASL Library.

+-------------+----------+---------+--------------------------------------------------------------------------+-----------------------------------------------------------+
| Mechanism   | Usage    | MAX SSF | SECURITY PROPERTIES                                                      | FEATURES                                                  |
|             |          |         +---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
|             |          |         | NOPLAIN | NOACTIVE | NODICT | FORWARD | NOANON | CRED | MUTUAL | QUANTUM | CLT FIRST | SRV FIRST    | SRV LAST | PROXY | BIND | HTTP |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| ANONYMOUS   | COMMON   |       0 | X       |          |        |         |        |      |        |         | X         |              |          |       |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| CRAM-MD5    | LIMITED  |      10 | X       |          |        |         | X      |      |        | X       |           | X            |          |       |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| DIGEST-MD5  | OBSOLETE |      10 | X       |          |        |         | X      |      | X      | X       | reauth    | initial auth | X        | X     |      | X    |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| EXTERNAL    | COMMON   |     128 | X       |          | X      |         | X      |      |        |         | X         |              |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| G2 ?        | unknown  |      56 | X       | X        |        |         | X      |      | X      | ?       | X         |              | X        | X     | X    |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| GSSAPI      | COMMON   |     128 | X       | X        |        |         | X      | X    | X      | X       | X         |              |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| GSS-SPNEGO  | LIMITED  |     128 | X       | X        |        |         | X      | X    | X      | X       | X         |              |          | X     |      | X    |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| KERBEROS_V4 | OBSOLETE |      56 | X       | X        |        |         | X      |      | X      | X       |           | X            |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| LOGIN       | OBSOLETE |       0 |         |          |        |         | X      | X    |        |         |           | X            |          |       |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| NTLM        | LIMITED  |       0 | X       |          |        |         | X      |      |        |         | X         |              |          |       |      | X    |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| OTP         | COMMON   |      10 | X       |          |        | X       | X      |      |        | X       | X         |              |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| PASSDSS     | unknown  |     112 | X       | X        | X      | X       | X      | X    | X      |         | X         |              |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| PLAIN       | COMMON   |       0 |         |          |        |         | X      | X    |        |         | X         |              |          | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| SCRAM       | COMMON   |      50 | X       | X        |        |         | X      |      | X      | X       | X         |              | X        | X     | X    | ?    |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+
| SRP         | unknown  |     128 | X       | X        | X      | X       | X      |      | X      |         | X         |              | X        | X     |      |      |
+-------------+----------+---------+---------+----------+--------+---------+--------+------+--------+---------+-----------+--------------+----------+-------+------+------+

..  Helpfully generated  from http://www.tablesgenerator.com/text_tables#

Understanding this table:

* **Usage** - As per the IANA registry on https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml

Security Properties:

* **MAX SSF** - The maximum Security Strength Factor supported by the mechanism (roughly the 2log of the search space for brute force attacks).  Set to 10 when the search space is only subject to password quality, 50 when effort is added.
* **NOPLAIN** - Mechanism is not susceptable to simple passive (eavesdropping) attack.
* **NOACTIVE** - Protection from active (non-dictionary) attacks during authentication exchange. (Implies MUTUAL).
* **NODICT** - Not susceptable to passive dictionary attack.
* **NOFORWARD** - Breaking one session won't help break the next.
* **NOANON** - Don't permit anonymous logins.
* **CRED** - Mechanism can pass client credentials.
* **MUTUAL** - Supports mutual authentication (authenticates the server to the client)
* **QUANTUM** - Protected from Quantum Computer attacks, or offers at least one such variety (which for authentication, unlike encryption, is not an issue until Quantum Computers actually emerge)

Features:

* **CLTFIRST** - The client should send first in this mechanism.
* **SRVFIRST** - The server must send first in this mechanism.
* **SRVLAST** - This mechanism supports server-send-last configurations.
* **PROXY** - This mechanism supports proxy authentication.
* **BIND** - This mechanism supports channel binding.
* **HTTP** - This mechanism has a profile for HTTP.

.. toctree::
    :hidden:

    gssapi
