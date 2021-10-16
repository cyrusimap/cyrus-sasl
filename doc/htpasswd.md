Here are information about auth htpasswd. 
## Build
To build this extension you have to install apr library:
```shell script
apt-get install libaprutil1-dev
``` 
and enable it with configure script:
```shell script
./configure --enable-htpasswd
```
the do the rest:
```shell script
make 
make install
```
when everything is done correct `./saslauthd` will output:
```
authentication mechanisms: getpwent rimap shadow htpasswd
```

## Usage/configuration
Only thing to needs to be configured is the location of htpasswd file
and it is passed with `-O` option:
```shell script
saslauthd -a htpasswd O /path/to/htpasswd
```

## Test it
Create htpasswd file (it requires `apache2-utils`):
```shell script
htpasswd -bc .htpasswd test1 password1
```
Run in debug mode (only for testing)
```shell script
sudo saslauthd -d -a htpasswd O .htpasswd
```

Test with `testsaslauthd`:
```shell script
testsaslauthd -u test1 -p password1
```

If there is any problem with auth method additional logs
can be found is `auth.log`.