CC=gcc -g -Wall
CFLAGS=-I/usr/local/include/sfio
LDFLAGS=-L/usr/local/lib -L/usr/local/lib/sfio

all: imtest smtptest saslpasswd

imtest: imtest.o sfsasl.o
	$(CC) $(LDFLAGS) imtest.o sfsasl.o -o imtest -lsfio -lsasl -ldl

smtptest: smtptest.o sfsasl.o
	$(CC) $(LDFLAGS) smtptest.o sfsasl.o -o smtptest -lsfio -lsasl -ldl

saslpasswd: saslpasswd.o
	$(CC) $(LDFLAGS) saslpasswd.o -o saslpasswd -lsasl -ldl

clean:
	rm -f imtest.o sfsasl.o imtest smtptest.o smtptest saslpasswd saslpasswd.o
