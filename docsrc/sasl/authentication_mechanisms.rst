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
| EXTERNAL    | 0       | X       |          | X      |         | X      |      |        | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GS2         | 0       | X       | X        |        |         | X      |      | X      | X         |              | X        | X     | X    |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GSSAPI      | 256     | X       | X        |        |         | X      | X    | X      | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| GSS-SPNEGO  | 256     | X       | X        |        |         | X      | X    | X      | X         |              |          | X     |      | X    |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| PLAIN       | 0       |         |          |        |         | X      | X    |        | X         |              |          | X     |      |      |
+-------------+---------+---------+----------+--------+---------+--------+------+--------+-----------+--------------+----------+-------+------+------+
| SCRAM       | 0       | X       | X        |        |         | X      |      | X      | X         |              | X        | X     | X    | X    |
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
