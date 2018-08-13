.. saslman:: sasl_client_plug_init_t(3)

.. _sasl-reference-manpages-library-sasl_client_plug_init_t:

========================================================
**sasl_client_plug_init_t** - client plug‐in entry point
========================================================

Synopsis
========

.. code-block:: C

    #include <sasl/saslplug.h>

    int sasl_client_plug_init_t(const sasl_utils_t *utils,
                                          int max_version,
                                         int *out_version,
                            sasl_client_plug_t **pluglist,
                                           int *plugcount);

Description
===========

.. c:function::  int sasl_client_plug_init_t(const sasl_utils_t *utils,
        int max_version,
        int *out_version,
        sasl_client_plug_t **pluglist,
        int *plugcount);

    The **sasl_client_plug_init_t** callback function is the client
    plugin entry point.

    :param utils: The utility callback functions.

    :param max_version: The highest client plugin version supported.

    :param out_version: The client plugin version of the result.

    :param pluglist: The list of client mechanism plugins.

    :param plugcount: The number of client mechanism plugins.

    :returns: Returns  :c:macro:`SASL_OK` on success. See
        :saslman:`sasl_errors(3)` for meanings of other return codes.

Return Value
============

SASL functions should return SASL return codes.
See sasl.h for a complete list. :c:macro:`SASL_OK` indicates success.


Conforming to
=============

:rfc:`4422`

See Also
========

:saslman:`sasl(3)`, :saslman:`sasl_errors(3)`
