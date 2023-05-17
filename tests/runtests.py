#!/usr/bin/python3

import argparse
import base64
import os
import shutil
import signal
import subprocess
import sys
import time
from string import Template


def setup_socket_wrappers(testdir):
    """ Try to set up socket wrappers """
    wrapdir = os.path.join(testdir, 'w')
    os.makedirs(wrapdir)

    wrappers = subprocess.Popen(['pkg-config', '--exists', 'socket_wrapper'])
    wrappers.wait()
    if wrappers.returncode != 0:
        raise Exception('Socket Wrappers not available')

    wrappers = subprocess.Popen(['pkg-config', '--exists', 'nss_wrapper'])
    wrappers.wait()
    if wrappers.returncode != 0:
        raise Exception('NSS Wrappers not available')

    hosts = os.path.join(wrapdir, 'hosts')
    with open(hosts, 'w+') as conffile:
        conffile.write('127.0.0.9 host.realm.test')

    return {'LD_PRELOAD': 'libsocket_wrapper.so libnss_wrapper.so',
            'SOCKET_WRAPPER_DIR': wrapdir,
            'SOCKET_WRAPPER_DEFAULT_IFACE': '9',
            'NSS_WRAPPER_HOSTNAME': 'host.realm.test',
            'NSS_WRAPPER_HOSTS': hosts}


KERBEROS_CONF = '''
[libdefaults]
  default_realm = REALM.TEST
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  ticket_lifetime = 24h
  forwardable = yes
  default_ccache_name = FILE://${TESTDIR}/ccache
  udp_preference_limit = 1

[domain_realm]
  .realm.test = REALM.TEST
  realm.test = REALM.TEST

[realms]
 REALM.TEST = {
  kdc = 127.0.0.9
  admin_server = 127.0.0.9
  acl_file = ${TESTDIR}/kadm.acl
  dict_file = /usr/share/dict/words
  admin_keytab = ${TESTDIR}/kadm.keytab
  database_name = ${TESTDIR}/kdc.db
  key_stash_file = ${TESTDIR}/kdc.stash
 }

[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88

[logging]
  kdc = FILE:${TESTDIR}/kdc.log
  admin_server = FILE:${TESTDIR}/kadm.log
  default = FILE:${TESTDIR}/krb5.log
'''


def setup_kdc(testdir, env):
    """ Setup KDC and start process """
    krbconf = os.path.join(testdir, 'krb.conf')
    env['KRB5_CONFIG'] = krbconf

    kenv = {'KRB5_KDC_PROFILE': krbconf,
            'PATH': '/sbin:/bin:/usr/sbin:/usr/bin'}
    kenv.update(env)

    # KDC/KRB5 CONFIG
    templ = Template(KERBEROS_CONF)
    text = templ.substitute({'TESTDIR': testdir})
    with open(krbconf, 'w+') as conffile:
        conffile.write(text)

    testlog = os.path.join(testdir, 'kdc.log')
    log = open(testlog, 'a')

    subprocess.check_call([
        "kdb5_util", "create",
        "-r", "REALM.TEST", "-s", "-P", "password"
        ], stdout=log, stderr=log, env=kenv, timeout=5)

    kdc = subprocess.Popen(['krb5kdc', '-n'], env=kenv, preexec_fn=os.setsid)
    time.sleep(5)

    # Add a user and genrate a keytab
    keytab = os.path.join(testdir, "user.keytab")
    subprocess.check_call([
        "kadmin.local", "-q",
        "addprinc -randkey user"
        ], stdout=log, stderr=log, env=kenv, timeout=5)

    subprocess.check_call([
        "kadmin.local", "-q",
        "ktadd -k {} user".format(keytab)
        ], stdout=log, stderr=log, env=kenv, timeout=5)
    env['KRB5_CLIENT_KTNAME'] = keytab

    # Add a service and genrate a keytab
    keytab = os.path.join(testdir, "test.keytab")
    subprocess.check_call([
        "kadmin.local", "-q",
        "addprinc -randkey test/host.realm.test"
        ], stdout=log, stderr=log, env=kenv, timeout=5)
    subprocess.check_call([
        "kadmin.local", "-q",
        "addprinc -randkey test/random.realm.test"
        ], stdout=log, stderr=log, env=kenv, timeout=5)

    subprocess.check_call([
        "kadmin.local", "-q",
        "ktadd -k {} test/host.realm.test".format(keytab)
        ], stdout=log, stderr=log, env=kenv, timeout=5)
    subprocess.check_call([
        "kadmin.local", "-q",
        "ktadd -k {} test/random.realm.test".format(keytab)
        ], stdout=log, stderr=log, env=kenv, timeout=5)
    env['KRB5_KTNAME'] = keytab

    return kdc, env

def gssapi_basic_test(kenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_channel_binding_test(kenv):
    try:
        bindings = base64.b64encode("MATCHING CBS".encode('utf-8'))
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-c", bindings],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-c", bindings],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_accept_any_test(kenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-p", "*"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-h", "random.realm.test"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_service_principal_test(kenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-p", "test@random.realm.test"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-h", "random.realm.test"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=10)
            srv.wait(timeout=10)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_keytab_test(kenv):
    try:
        newkenv = dict(kenv)
        del newkenv['KRB5_KTNAME']
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-k", kenv['KRB5_KTNAME']],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=newkenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_channel_binding_mismatch_test(kenv):
    result = "FAIL"
    try:
        bindings = base64.b64encode("SRV CBS".encode('utf-8'))
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-c", bindings],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        bindings = base64.b64encode("CLI CBS".encode('utf-8'))
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-c", bindings],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            cli_err = cli.stderr.read().decode('utf-8').strip()
            srv_err = srv.stderr.read().decode('utf-8').strip()
            if "authentication failure" in srv_err:
                result = "PASS"
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli_err, srv.returncode, srv_err))
    except Exception as e:
        print("{}: {}".format(result, e))
        return 0

    print("FAIL: This test should fail [CLI({}) SRV({})]".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 1

def gss_spnego_basic_test(kenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-N"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-N"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gss_spnego_zeromaxssf_test(kenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-N", "-z"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-N", "-z"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=kenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return 1

    print("PASS: CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return 0

def gssapi_tests(testdir):
    """ SASL/GSSAPI Tests """
    env = setup_socket_wrappers(testdir)
    kdc, kenv = setup_kdc(testdir, env)
    #print("KDC: {}, ENV: {}".format(kdc, kenv))
    kenv['KRB5_TRACE'] = os.path.join(testdir, 'trace.log')

    err = 0

    print('GSSAPI BASIC:')
    print('    ', end='')
    err += gssapi_basic_test(kenv)

    print('GSSAPI ACCEPT ANY:')
    print('    ', end='')
    err += gssapi_accept_any_test(kenv)

    print('GSSAPI SERVICE PRINCIPAL:')
    print('    ', end='')
    err += gssapi_service_principal_test(kenv)

    print('GSSAPI KEYTAB:')
    print('    ', end='')
    err += gssapi_keytab_test(kenv)

    print('GSSAPI CHANNEL BINDING:')
    print('    ', end='')
    err += gssapi_channel_binding_test(kenv)

    print('GSSAPI CHANNEL BINDING MISMTACH:')
    print('    ', end='')
    err += gssapi_channel_binding_mismatch_test(kenv)

    print('GSS-SPNEGO BASIC:')
    print('    ', end='')
    err += gss_spnego_basic_test(kenv)

    print('GSS-SPNEGO 0 MAXSSF:')
    print('    ', end='')
    err += gss_spnego_zeromaxssf_test(kenv)

    os.killpg(kdc.pid, signal.SIGTERM)
    return err

def setup_plain(testdir):
    """ Create sasldb file """
    sasldbfile = os.path.join(testdir, 'testsasldb.db')

    sasldbenv = {'SASL_PATH': os.path.join(testdir, '../../plugins/.libs'),
                 'LD_LIBRARY_PATH' : os.path.join(testdir, '../../lib/.libs')}

    passwdprog = os.path.join(testdir, '../../utils/saslpasswd2')

    echo = subprocess.Popen(('echo', '1234567'), stdout=subprocess.PIPE)
    subprocess.check_call([
        passwdprog, "-f", sasldbfile, "-c", "test",
        "-u", "host.realm.test", "-p"
        ], stdin=echo.stdout, env=sasldbenv, timeout=5)

    return (sasldbfile, sasldbenv)

def plain_test(sasldbfile, sasldbenv):
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-P", sasldbfile],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=sasldbenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-P", "1234567"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=sasldbenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli.stderr.read().decode('utf-8'),
                srv.returncode, srv.stderr.read().decode('utf-8')))
    except Exception as e:
        print("FAIL: {}".format(e))
        return

    print("PASS: PLAIN CLI({}) SRV({})".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return

def plain_mismatch_test(sasldbfile, sasldbenv):
    result = "FAIL"
    try:
        srv = subprocess.Popen(["../tests/t_gssapi_srv", "-P", sasldbfile],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=sasldbenv)
        srv.stdout.readline() # Wait for srv to say it is ready
        bindings = base64.b64encode("CLI CBS".encode('utf-8'))
        cli = subprocess.Popen(["../tests/t_gssapi_cli", "-P", "12345678"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=sasldbenv)
        try:
            cli.wait(timeout=5)
            srv.wait(timeout=5)
        except Exception as e:
            print("Failed on {}".format(e));
            cli.kill()
            srv.kill()
        if cli.returncode != 0 or srv.returncode != 0:
            cli_err = cli.stderr.read().decode('utf-8').strip()
            srv_err = srv.stderr.read().decode('utf-8').strip()
            if "authentication failure" in srv_err:
                result = "PASS"
            raise Exception("CLI ({}): {} --> SRV ({}): {}".format(
                cli.returncode, cli_err, srv.returncode, srv_err))
    except Exception as e:
        print("{}: {}".format(result, e))
        return

    print("FAIL: This test should fail [CLI({}) SRV({})]".format(
        cli.stdout.read().decode('utf-8').strip(),
        srv.stdout.read().decode('utf-8').strip()))
    return

def plain_tests(testdir):
    sasldbfile, sasldbenv = setup_plain(testdir)
    #print("DB file: {}, ENV: {}".format(sasldbfile, sasldbenv))
    print('SASLDB PLAIN:')
    print('    ', end='')
    plain_test(sasldbfile, sasldbenv)

    print('SASLDB PLAIN PASSWORD MISMATCH:')
    print('    ', end='')
    plain_mismatch_test(sasldbfile, sasldbenv)

if __name__ == "__main__":

    P = argparse.ArgumentParser(description='Cyrus SASL Tests')
    P.add_argument('--testdir', default=os.path.join(os.getcwd(), '.tests'),
                   help="Directory for running tests")
    A = vars(P.parse_args())

    T = A['testdir']

    if os.path.exists(T):
        shutil.rmtree(T)
    os.makedirs(T)

    plain_tests(T)

    err = gssapi_tests(T)
    if err != 0:
        print('{} test(s) FAILED'.format(err))
        sys.exit(-1)
