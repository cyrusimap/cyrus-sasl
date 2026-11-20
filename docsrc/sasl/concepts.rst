Concepts
========

SASL
----

Simple Authentication and Security Layer (SASL) is a protocol developed by the Internet Engineering Task Force (IETF) for the purpose of providing an extensible and pluggable authentication framework, primarily for non-web related protocols. It is commonly used in email related protocols, such as SMTP, IMAP, and POP, along with XMPP, LDAP, and a few others. In doing so, various implementations of those protocols, such as the Cyrus IMAP or Dovecot servers, can support a wide range of authentication mechanisms with various email clients which implement the IMAP protocol, including Thunderbird, Outlook, and the Android mail client.

RFC 4422 is the base framework specification for SASL. It provides guidance for protocol designers, server software implementations, and SASL mechanism designers. Protocol definitions, and SASL mechanism specifications in turn make use of this framework to independently support each other. That is, if a protocol were designed 5 years ago to make use of SASL, and a new mechanism were designed today, server implementations and client software could make use of that new mechanism without a change to the original server protocol spec.

SASL Authentication Mechanisms
------------------------------

SASL mechanisms are plugable authentication methods that are developed independently of server protocols. For example, the Generic Security Service Application Program Interface (GSSAPI) mechanism, defined in RFC 4752, defines a network oriented protocol for authenticating a client to a server, using Kerberos version 5, a trusted 3rd party ticket based system. The GSSAPI mechanism should work with all clients and servers which implement support for it, regardless of the actual server protocol used (such as IMAP), given the protocol was designed for use with the SASL framework.

A list of developed SASL mechanisms can be found at the `IANA registered SASL mechanisms <https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xml>`__ page. A more detailed discussion of these mechanisms can be found in :doc:`Authentication Mechanisms<authentication_mechanisms>`.

Security Layers
---------------

SASL Security Layers allow a server and client to negotiate integrity and confidentiality protection for a connection once it has been authenticated. It is only available for mechanisms which themselves are capable of providing such protection (such as GSSAPI). It is capable of being used to encrypt a connection over the public internet, and can be used as an alternative to TLS encryption.

Channel Binding
---------------

Channel binding ties a SASL authentication to the TLS connection it runs
over. Client and server each fold data identifying their end of the TLS
channel into the exchange, and it only succeeds if both saw the same channel,
so an attacker who terminates TLS in the middle (with a forged certificate,
say) can't relay it. Mechanisms support it through their "-PLUS" variants,
such as ``SCRAM-SHA-256-PLUS`` and ``GS2-KRB5-PLUS``.

The library doesn't talk to TLS itself: the application supplies the binding.
After the TLS handshake, and before ``sasl_client_start()`` or
``sasl_server_start()``, set the ``SASL_CHANNEL_BINDING`` property to a
``sasl_channel_binding_t`` holding the binding type's ``name``, its ``data``
and ``len``, and ``critical``:

* With ``critical`` set, a client only uses a mechanism that binds the
  channel, and a server only offers "-PLUS" variants and refuses clients that
  don't bind.
* Without it, binding is used when both sides support it, and a client that
  supports it but doesn't see a "-PLUS" variant offered says so, which lets a
  server that does offer one detect that it was stripped.

**Which binding type.** The library never chooses one; use the type that
matches the TLS version:

.. list-table::
   :header-rows: 1

   * - TLS version
     - Type
     - Data
   * - 1.3
     - ``tls-exporter`` (:rfc:`9266`)
     - 32 bytes of TLS exported keying material with the label
       ``EXPORTER-Channel-Binding`` and an empty context
   * - 1.2
     - ``tls-unique`` (:rfc:`5929`)
     - The first TLS Finished message of the connection. Only safe with the
       extended master secret extension (:rfc:`7627`)
   * - Any
     - ``tls-server-end-point`` (:rfc:`5929`)
     - A hash of the server's certificate. Weaker: it binds to the server's
       certificate rather than to the connection

:rfc:`9266` makes ``tls-exporter`` the default, and mandatory to implement,
over TLS 1.3, where ``tls-unique`` isn't defined; ``tls-unique`` stays the
default over TLS 1.2. With OpenSSL, the ``tls-exporter`` data is::

    unsigned char cb[32];
    SSL_export_keying_material(ssl, cb, sizeof(cb),
                               "EXPORTER-Channel-Binding", 24,
                               NULL, 0, 1);

A client tells the server which type it used. A server that can provide
other types too can register a ``SASL_CB_SERVER_CHANNEL_BINDING`` callback,
which is asked for the type the client requested when it differs from the one
set with ``SASL_CHANNEL_BINDING``.

Realms
------

.. todo::
   What are realms?

Protocols
---------

.. todo::
   What protocols?

Cyrus SASL
----------

.. todo::
   Something required here

The Glue Library
----------------

.. todo::
   A bit stuck with this one too :)

Auxiliary Properties
--------------------

.. todo::
   More properties...

Plugins
-------

.. todo::
   Plugins, plugins and plugins
