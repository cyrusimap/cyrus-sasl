.. _authentication_mechanisms:

=========================
Authentication Mechanisms
=========================

Mechanisms
==========

ANONYMOUS
---------

This mechanism does not require the client to authenticate or provide any information.

Defined in :rfc:`2245`

.. _MECH-CRAM-MD5:

CRAM-MD5
--------

This mechanism avoids sending the users password over the network in plain text by hashing the password with a server provided random value (known as a nonce).
A disadvantage of this mechanism is that the server must maintain a database of **plaintext passwords** for comparison.

CRAM-MD5 does not provide adequate security services for use on the Internet, it does not protect the user's authentication identifier from eavesdroppers and is subject to a number of passive and active attacks.

Defined in :rfc:`2195`

Documented in a `RFC Draft: draft-ietf-sasl-crammd5 <https://tools.ietf.org/html/draft-ietf-sasl-crammd5>`_

.. warning::
   The CRAM-MD5 SASL mechanism is obsolete. It has been moved to Historic in `draft-ietf-sasl-crammd5-to-historic <https://tools.ietf.org/html/draft-ietf-sasl-crammd5-to-historic-00>`_

DIGEST-MD5
----------

This mechanism improves upon the :ref:`MECH-CRAM-MD5` mechanism by avoiding the need for the server to store plaintext passwords.
With digest authentication the server needs to store the **MD5 digest** of the users password which helps to make the system more secure.
As in :ref:`MECH-CRAM-MD5` the password is hashed with a server nonce and other data before being transmitted across the network.

Defined in :rfc:`2831`

EXTERNAL
--------

EXTERNAL is a SASL Mechanism that allows a client to request the server to use credentials established by means external to the mechanism to authenticate the client.

SASL EXTERNAL means may be, for instance, IP Security (:rfc:`4301`) or TLS services.
In absence of a prior agreement between the client and the server, the client cannot make any assumption as to what SASL EXTERNAL means the server has used to obtain the client's credentials, nor make an assumption as to the form of credentials.
For example, the client cannot assume that the server will use the credentials the client has established via TLS.

.. note::
   The server will not offer EXTERNAL unless other credentials are already available in the session, such as a client certificate used in establishing a TLS connection.

GS2
-----

Generic Security Service Application Program Interface (GSS-API).
The GS2 mechanism family offers a number of improvements over the previous :ref:`GSSAPI` mechanism.

Defined in :rfc:`5801`

.. _MECH-GSSAPI:

GSSAPI
------

Not sure how to get GSSAPI going? Check out our :ref:`GSSAPI configuration guide <gssapi>`.

.. todo::
   Content needed here


GSS-SPNEGO
----------

This is a Microsoft specific customization of GSSAPI.

Described in the `Microsoft documentation <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e1cbe214-d73b-4c58-aad2-bee399ccdfb8>`_ and :rfc:`4178`

LOGIN
-----

Documented in a `RFC Draft: draft-murchison-sasl-login <https://tools.ietf.org/html/draft-murchison-sasl-login>`_

.. warning::
   The LOGIN SASL mechanism is obsoleted in favor of the :ref:`MECH-PLAIN` SASL mechanism.

The LOGIN SASL mechanism does not provide a security layer.
This mechanism must not be used without adequate security protection as
the mechanism affords no integrity nor confidentiality protection itself.

OTP
---

OTP is the One-Time Password system described in :rfc:`2289`.
This mechanism is secure against replay attacks and also avoids storing password or password equivalents on the server.
Only a digest of a seed and a passphrase is ever transmitted across the network.

  * OTP-MD4
  * OTP-MD5
  * OTP-SHA1

.. todo::
   Content needed here

PASSDSS
-------

DSS Secured Password Authentication Mechanism (PASSDSS)

Documented in a `RFC Draft: draft-newman-sasl-passdss <https://tools.ietf.org/html/draft-newman-sasl-passdss>`_

  * PASSDSS-3DES-1

.. _MECH-PLAIN:

PLAIN
-----

Defined in :rfc:`4616`

This is the simplest mechanism.
The users authentication details are transmitted in plain text.
This mechanism should not be provided unless an encrypted link is in use - typically after TLS has been negotiated.

SCRAM
-----

Salted Challenge Response Authentication Mechanism (SCRAM) is a family of modern, password-based challenge–response authentication mechanisms providing authentication of a user to a server.

Defined in :rfc:`5802`

  * SCRAM-SHA-1(-PLUS)
  * SCRAM-SHA-224(-PLUS)
  * SCRAM-SHA-256(-PLUS) (:rfc:`7677`)
  * SCRAM-SHA-384(-PLUS)
  * SCRAM-SHA-512(-PLUS)

SRP
---

The Secure Remote Password (SRP) is a password-based, zero-knowledge,
authentication and key-exchange protocol.
It has good performance, is not plaintext-equivalent and maintains perfect forward secrecy.
It provides authentication (optionally mutual authentication) and the negotiation of a shared context key.

Documented in a `RFC Draft: draft-burdis-cat-srp-sasl <https://tools.ietf.org/html/draft-burdis-cat-srp-sasl-08>`_

  * mda=sha1,rmd160,md5
  * confidentiality=des-ofb,des-ede-ofb,aes-128-ofb,bf-ofb,cast5-ofb,idea-ofb

Non-SASL Authentication
-----------------------

.. todo::
   Content needed here

----

Summary
=======

This table shows what security flags and features are supported by each
of the mechanisms provided by the Cyrus SASL Library.

+-------------+---------+----------------------------------------------------------------+-----------------------------------------------------------+
|             | MAX SSF | SECURITY PROPERTIES                                            | FEATURES                                                  |
+-------------+         +---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
|             |         | NOPLAIN | NOACTIVE | NODICT | FORWARD | NOANON | CRED | MUTUAL | CLT FIRST | SRV FIRST    | SRV LAST | PROXY | BIND | HTTP |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| ANONYMOUS   | 0       | X       |          |        |         |        |      |        | X         |              |          |       |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| CRAM-MD5    | 0       | X       |          |        |         | X      |      |        |           | X            |          |       |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| DIGEST-MD5  | 128     | X       |          |        |         | X      |      | X      | reauth    | initial auth | X        | X     |      | X    |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| EXTERNAL    | 0       | X       |          | X      |         | X      |      |        | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GS2         | 56      | X       | X        |        |         | X      |      | X      | X         |              | X        | X     | X    |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GSSAPI      | 56      | X       | X        |        |         | X      | X    | X      | X         |              |          | X     | X    |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GSS-SPNEGO  | 56      | X       | X        |        |         | X      | X    | X      | X         |              |          | X     |      | X    |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| LOGIN       | 0       |         |          |        |         | X      | X    |        |           | X            |          |       |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| OTP         | 0       | X       |          |        | X       | X      |      |        | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| PASSDSS     | 112     | X       | X        | X      | X       | X      | X    | X      | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| PLAIN       | 0       |         |          |        |         | X      | X    |        | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| SCRAM       | 0       | X       | X        |        |         | X      |      | X      | X         |              | X        | X     | X    | X    |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| SRP         | 128     | X       | X        | X      | X       | X      |      | X      | X         |              | X        | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+

..  Helpfully generated  from https://www.tablesgenerator.com/text_tables

Understanding this table:

Security Properties:

* **MAX SSF** - The maximum Security Strength Factor supported by the mechanism (roughly the number of bits of encryption provided, but may have other meanings, for example an SSF of 1 indicates integrity protection only, no encryption).
* **NOPLAIN** - Mechanism is not susceptible to simple passive (eavesdropping) attack.
* **NOACTIVE** - Protection from active (non-dictionary) attacks during authentication exchange. (Implies MUTUAL).
* **NODICT** - Not susceptible to passive dictionary attack.
* **NOFORWARD** - Breaking one session won't help break the next.
* **NOANON** - Don't permit anonymous logins.
* **CRED** - Mechanism can pass client credentials.
* **MUTUAL** - Supports mutual authentication (authenticates the server to the client)

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
