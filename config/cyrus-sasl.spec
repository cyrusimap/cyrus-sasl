Summary: SASL API Implementation
Name: cyrus-sasl
Version: v1.3b1
Release: 1
Copyright: CMU
Group: Libraries
Source: ftp.andrew.cmu.edu:/pub/cyrus-mail/cyrus-sasl-v1.3b1.tar.gz
Packager: Rob Earhart <earhart@cmu.edu>
Prefix: /usr

%description
This package implements the SASL API, useful for adding
authentication, authorization, and security to network protocols, and
contains implementations of several SASL mechanisms.  The SASL
protocol itself is documented in rfc2222; the API standard is a work
in progress.

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
/usr/lib/sasl
/usr/lib/libsasl.so.4.0.0
/usr/lib/libsasl.so.4
/usr/lib/libsasl.so
/usr/lib/libsasl.la
/usr/include/sasl.h
/usr/include/saslplug.h
/usr/include/saslutil.h
/usr/include/md5global.h
/usr/include/md5.h
/usr/include/hmac-md5.h
/usr/sbin/saslpasswd
/usr/man/man8/saslpasswd.8
