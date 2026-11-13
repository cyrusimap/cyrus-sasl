.. _install-macos:

======================================
Building and using Cyrus SASL on macOS
======================================

The Cyrus SASL distribution builds on macOS like on other Unix-like
systems. It installs the following components:

* The SASL library, ``libsasl2.dylib``, in ``$libdir`` (by default
  ``/usr/local/lib``), with its plugins in ``$libdir/sasl2``.
* A framework in ``/Library/Frameworks/SASL2.framework``, which allows
  the use of the ``-framework`` option to Apple's ``ld``. The framework
  is a wrapper around a symlink to ``libsasl2.dylib`` with the
  information needed to recognize it as a framework. Pass
  ``--disable-macos-framework`` to ``configure`` to skip it.

Compiling and Using the library
===============================

Building from GIT requires the GNU autotools (autoconf, automake and
libtool), which can be installed with a package manager such as
`Homebrew <https://brew.sh>`_ or `MacPorts <https://www.macports.org>`_.

You must be root to ``make install`` into ``/usr/local``, for example
by using ``sudo``. ``make install`` also adds the framework to
``/Library/Frameworks``.
