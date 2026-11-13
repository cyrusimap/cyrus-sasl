.. saslman:: sasl_getconfpath_t(3)

.. _sasl-reference-manpages-library-sasl_getconfpath_t:


===================================================================================
**sasl_getconfpath_t** - The SASL callback to indicate location of the config files
===================================================================================

Synopsis
========

.. code-block:: C

    #include <sasl/sasl.h>

    int sasl_getconfpath_t(void *context, char ** path);


Description
===========

.. c:function:: int sasl_getconfpath_t(void *context, char ** path);

    **sasl_getconfpath_t()** is used if the  application  wishes  to
    use a different location for the SASL configuration files.
    If this callback is not used  SASL  will  either  use  the
    location  in the environment variable SASL_CONF_PATH (provided
    we are not SUID or SGID) or `/etc/sasl2` by default.

On success, any non-NULL string returned through ``path`` must be
heap-allocated with the allocator registered through :saslman:`sasl_set_alloc(3)`
(or the default allocator). Ownership transfers to the library, which frees
the string after loading the configuration. Do not return a static string or
retain ownership of the returned allocation.

Return Value
============

SASL  callback  functions should return SASL return codes.
See sasl.h for a complete list. :c:macro:`SASL_OK` indicates success.

Other return codes indicate errors and should be handled.

See Also
========

:rfc:`4422`,:saslman:`sasl(3)`, :saslman:`sasl_callbacks(3)`
