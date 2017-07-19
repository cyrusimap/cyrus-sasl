============================
Cyrus SASL 1.x Release Notes
============================

New in 1.5.26
-------------
* Interoperability bug in DIGEST-MD5's layers was fixed.
* DIGEST-MD5's DES layer has been disabled until the interoperability
  can be worked out.

New in 1.5.25
-------------

* The DIGEST-MD5 plugin now includes an implementation of RC4, since
  it's a lot easier to get working than interfacing with OpenSSL.
* A delayed-open plugin mode has been implemented, but not yet documented.

New in 1.5.24
-------------
* be a little paranoid about what we give PAM
* small bugfixes

New in 1.5.22
-------------
* fixed some DIGEST-MD5 buglets
* fixed serious bug that a client could avoid the authorization callback
* added pwcheck method "sia" for Digital Unix
* now should try libdb-3 before libdb.

New in 1.5.21
-------------
* build process fixes

New in 1.5.20
-------------
* bug fixes
* LOGIN mechanism has a compatibility tweak

New in 1.5.19
-------------
* Initial srp work
* Programmers Guide more complete
* bug fixes (of course)

New in 1.5.18
-------------
* javasasl library in conformance with internet draft
* man pages for all functions written
* bug fixes (of course)

New in 1.5.17
-------------
* give application authentication name and realm more uniformly
* sasldblistusers utility to list users in sasldb
* memory leaks eliminated; boundary cases tested

New in 1.5.16
-------------
* pwcheck_method now defaults to sasldb.
  READ UPGRADE INSTRUCTIONS IN README

* sanity checking inputs throughout the code.
* Unsupported LOGIN plugin added to the Windows build.
* calling sasl_checkpass() with pwcheck_method: kerberos_v4 restores the
  old ticket file before returning.

New in 1.5.15
-------------
* configure now correctly detects Berkeley DB 3.x (Claus Assmann).

New in 1.5.14
-------------
* Upgraded to libtool 1.3.4.
* External SSF handled more uniformly, and handle min/max SSF requests
  correctly.
* Unsupported LOGIN plugin added, by Rainer Schoepf <schoepf@uni-mainz.de>.
  Please don't enable it unless you know you need it.
* HP/UX support, contributed by Claus Assmann.

New in 1.5.13
-------------
* Sanity check to make sure there's at least something in sasldb
  READ UPGRADE INSTRUCTIONS IN README

* Fixes to how external layers are handled (some fixes by Alexey Melnikov)
* Berkeley DB 3.x support contributed by Greg Shapiro
* Additional pwcheck fixes (Joe Hohertz)
* Fixed Heimdal krb5 configure checks
* other random fixes

New in 1.5.12
-------------
* lots of bugfixes
* DIGEST-MD5 more in conformance with spec
* support for Berkeley DB
* support for OpenSSL's version of RC4

New in 1.5.11
-------------
* bugfix in realm support for DIGEST-MD5

New in 1.5.10
-------------
* DIGEST-MD5 layer support
* dbconversion utility added

New in 1.5.9
------------
* Bug fixes
* More win32 support
* Realm support in the database (database format changed again, sorry)
  Other realm support in plugins; need to document it
* Preliminary code for pwcheck added; not yet tested (and probably not
  working)
* config stuff should be less case/whitespace sensitive
* more error conditions logged

New in 1.5.5
------------
* Bug fixes
* sasldb plaintext support (database format changed!!!)
* Handles multiple realms in DIGEST
* New Windows compatibility (tested!)

New in 1.5.3
------------
* Bug fixes
* Tested GSSAPI & added layers
* Some changes for Windows compatibility (next release)

New in 1.5.2
------------
* A few bug fixes
* Better portability
* Upgraded libtool

New in 1.5.0
------------
* Lots of bug fixes
* A few API changes (watch especially sasl_get_prop() and sasl_set_prop()!)
* Digest authentication works
* Configuration file
* Some more documentation (doc/programming)
* Code cleanup

New in 1.4.1
------------
* Tested kerberos4, cram, plain, and anonymous fairly extensively
* Many bugs fixed
* Created sample programs
* Added digest
* Prototype credential API

New in 1.3b1
------------
* Added saslpasswd for setting sasl passwords
* Added sfsasl for people using sfio
* Lots of bug fixes

New in 1.2b3
------------
* Slightly better documentation, easier compilation
* Plain now understands authorization and callbacks

New in 1.2b2
------------
* Win32 support
* Fixes to anonymous, kerberos mechs
* Some signed lengths in the API changed to unsigned

New in 1.2b1
------------
* Lots of bug fixes
* GSSAPI
* Cleaner getopt interface
* Cleaner plugin callback lookup interface
* Global inits now take callback list, not just a sasl_getopt_t
* Preliminary Java support
* Authentication database hook
* Default AuthDB routines moved from mechanisms to library
* Logging hook
* Default syslog-based logging hook in library
* Preliminary plaintext transition for CRAM/SCRAM
