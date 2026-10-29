.. saslman:: sasl_getcrypto_t(3)

.. _sasl-reference-manpages-library-sasl_getcrypto_t:

==========================================================
**sasl_getcrypto_t** - Select cryptographic operations
==========================================================

Synopsis
========

.. code-block:: C

    #include <sasl/sasl.h>

    int sasl_getcrypto_t(void *context, const char *algorithm,
                        const sasl_crypto_t **operations,
                        void **crypto_context);

Description
===========

Register this callback with the identifier ``SASL_CB_CRYPTO`` in a global
or connection callback array. It selects the hash, HMAC and PBKDF2-HMAC
operations used by SCRAM, APOP and legacy password verification. Connection
callbacks take precedence over global callbacks. The callback does not
replace random-number generation, password normalization or channel binding.

``context`` is the callback context. ``algorithm`` is a canonical hash name:
``MD5``, ``SHA1``, ``SHA224``, ``SHA256``, ``SHA384`` or ``SHA512``. On success,
set ``operations`` to an immutable ``sasl_crypto_t`` with version
``SASL_CRYPTO_VERSION`` and set ``crypto_context`` to the context passed to
its operations. The application owns both and keeps them valid until the
connection is disposed. Selection can occur during availability checks.
Shared contexts must be safe for concurrent connections.

``hash`` hashes concatenated input vectors; ``hmac`` computes HMAC;
``pbkdf2`` computes PBKDF2-HMAC with a nonzero iteration count. Output is
exactly the selected hash length, in bytes. Operations must fill the whole
output and return ``SASL_OK``, or return a negative SASL error. Inputs are
read-only, binary and length-delimited. A null input pointer is allowed only
with zero length. Hashing zero vectors and HMAC with an empty key or input
are valid. The library owns input and output; operations must not retain
their pointers or contents. Failed outputs are erased by the library.
``hash`` is mandatory; ``hmac`` and ``pbkdf2`` may be null for hash-only
backends. SCRAM requires all three.

When no callback is registered the built-in backend is used, if available.
A registered callback is authoritative: its errors and unsupported
algorithms never cause fallback to the built-in backend. Only the mechanisms
listed above use this callback; other mechanisms keep their dependencies.

Return Value
============

Return ``SASL_OK`` for successful selection, ``SASL_NOMECH`` for unsupported
algorithms, or another negative SASL error. Neither selection nor operations
may return ``SASL_INTERACT`` or ``SASL_CONTINUE``. Malformed tables are
rejected with ``SASL_BADPARAM``; unsupported table versions with
``SASL_BADVERS``.

See Also
========

:saslman:`sasl_callbacks(3)`, :ref:`programming`
