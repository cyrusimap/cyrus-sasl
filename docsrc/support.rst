.. _sasl-support:

=================
Support/Community
=================

Mailing List
============

Cyrus SASL is discussed on the `Cyrus SASL mailing list
<https://cyrus.topicbox.com/groups/sasl>`_, hosted by Topicbox.  You can browse
the archives and subscribe there, and you can ask for a daily summary if you
don't want to receive every message as it is sent.

Release announcements for all Cyrus software are sent to the low-traffic
`Cyrus Announcements <https://cyrus.topicbox.com/groups/announce>`_ list.

Reporting Bugs
==============

.. note::

    For **security issues**, please send your report to our private security
    list, security@cyrus.topicbox.com, rather than filing a public issue.

Bug reports can be sent to the mailing list or filed in the `Cyrus SASL issue
tracker <https://github.com/cyrusimap/cyrus-sasl/issues>`_ on GitHub.  When
reporting a bug, please include:

* your platform and, if applicable, your distribution and its version
* the exact version of Cyrus SASL you are using
* if you are using a packaged version, where the package came from
* if you built it yourself, the options you gave to ``configure``
* the application using SASL, and the mechanisms and plugins involved
* what you did, what you expected to happen, and what actually happened

Upstream version numbers like 2.1.28 don't say anything about how a package was
built or patched.  Most distributions can tell you the full package version with
``rpm -q cyrus-sasl`` or ``dpkg -l 'libsasl2*'``.  If you are running a build
from git, please say so, and say which commit.

If you know how to fix the bug, we're happy to receive a pull request.

Governance
==========

Cyrus SASL is managed under its own :doc:`bylaws <bylaws>`.
