Summary: SASL API implementation
Name: sasl
Version: 2.0.1
Release: 1
Copyright: CMU
Group: Libraries
Source: ftp.andrew.cmu.edu:/pub/cyrus-mail/cyrus-sasl-2.0.1-ALPHA.tar.gz
Packager: Rob Earhart <earhart@cmu.edu>
Requires: gdbm

%description
This is an implemention of the SASL API, useful for adding
authentication, authorization, and security to network protocols.  The
SASL protocol itself is documented in rfc2222; the API standard is a
work in progress.

%package devel
%summary: SASL development headers and examples

%description devel
This includes the header files and documentation needed to develop
applications which use SASL.

%package plug-anonymous
%summary: SASL ANONYMOUS mechanism plugin

%description plug-anonymous
This plugin implements the SASL ANONYMOUS mechanism,
used for anonymous authentication.

%package plug-plain
%summary: SASL PLAIN mechanism plugin

%description plug-plain
This plugin implements the SASL PLAIN mechanism.  Although insecure,
PLAIN is useful for transitioning to new security mechanisms, as this
is the only mechanism which gives the server a copy of the user's
password.

%package plug-scram
%summary: SASL SCRAM-SHA-1/SCRAM-SHA-2 mechanism plugin

%description plug-scram
This plugin implements the SASL SCRAM-SHA-1/SCRAM-SHA-2 mechanism.

%prep
%setup

%build
./configure --prefix=/usr
make

%install
make install

%post
if test $RPM_INSTALL_PREFIX/lib/sasl != /usr/lib/sasl; then
  ln -s $RPM_INSTALL_PREFIX/lib/sasl /usr/lib/sasl
fi

%postun
if test -L /usr/lib/sasl; then
  rm /usr/lib/sasl
fi

%files
%doc README COPYING ChangeLog NEWS AUTHORS
/usr/lib/libsasl.so.5.0.0
/usr/sbin/saslpasswd
/usr/man/man8/saslpasswd.8

%files devel
%doc doc/rfc2222.txt sample/sample-client.c sample/sample-server.c testing.txt
/usr/lib/libsasl.la
/usr/include/sasl.h
/usr/include/saslplug.h
/usr/include/saslutil.h

%files plug-anonymous
%doc doc/draft-newman-sasl-anon-00.txt
/usr/lib/sasl/libanonymous.so.1.0.2
/usr/lib/sasl/libanonymous.so

%files plug-plain
/usr/lib/sasl/libplain.so.1.0.1
/usr/lib/sasl/libplain.so
