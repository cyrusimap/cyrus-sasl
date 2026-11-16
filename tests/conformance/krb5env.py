"""A throwaway MIT Kerberos realm for the GSSAPI and GS2 tests.

Starts krb5kdc on a free localhost port with its own configuration, so no
root access, DNS, socket_wrapper or nss_wrapper is needed.  The realm has:

  user@TEST.REALM            the client; its keys are in a client keytab
                             (KRB5_CLIENT_KTNAME), so no kinit is needed
  test/host.test@TEST.REALM  the service the drivers use by default
                             (service "test", host "host.test")
  other/host.test@TEST.REALM a second service in the same keytab

The environment variables are set in os.environ, so the drivers (which
inherit it) and the Python GSS-API peer use the same realm.

Call require() from a test's setUp(): it starts the realm once per run, or
skips the test if the KDC tools or the Python gssapi module are missing.
"""

import atexit
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest

REALM = "TEST.REALM"
HOST = "host.test"
SERVICE = "test"
USER = "user"

TOOLS = ("krb5kdc", "kdb5_util", "kadmin.local")
TOOL_PATH = os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"])

KRB5_CONF = """\
[libdefaults]
  default_realm = {realm}
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  forwardable = true
  udp_preference_limit = 1
  default_ccache_name = FILE:{dir}/ccache

[realms]
  {realm} = {{
    kdc = 127.0.0.1:{port}
  }}

[domain_realm]
  {host} = {realm}
  .test = {realm}
"""

KDC_CONF = """\
[kdcdefaults]
  kdc_ports = {port}
  kdc_tcp_ports = {port}

[realms]
  {realm} = {{
    database_name = {dir}/principal
    key_stash_file = {dir}/stash
    acl_file = {dir}/kadm5.acl
    max_life = 1d
    max_renewable_life = 1d
  }}

[logging]
  kdc = FILE:{dir}/kdc.log
  default = FILE:{dir}/krb5.log
"""

_state = {"started": False, "skip": None, "dir": None, "kdc": None}


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _missing():
    try:
        import gssapi  # noqa: F401
    except ImportError:
        return "Python gssapi module not installed"
    missing = [t for t in TOOLS if not shutil.which(t, path=TOOL_PATH)]
    if missing:
        return "missing " + ", ".join(missing)
    return None


def _run(argv, env, log):
    tool = shutil.which(argv[0], path=TOOL_PATH)
    subprocess.check_call([tool] + argv[1:], env=env, stdout=log,
                          stderr=subprocess.STDOUT, timeout=30)


def _start():
    d = tempfile.mkdtemp(prefix="sasl-krb5-")
    _state["dir"] = d
    port = _free_port()
    fmt = {"realm": REALM, "host": HOST, "dir": d, "port": port}
    with open(os.path.join(d, "krb5.conf"), "w") as f:
        f.write(KRB5_CONF.format(**fmt))
    with open(os.path.join(d, "kdc.conf"), "w") as f:
        f.write(KDC_CONF.format(**fmt))
    open(os.path.join(d, "kadm5.acl"), "w").close()

    env = dict(os.environ)
    env.update({
        "KRB5_CONFIG": os.path.join(d, "krb5.conf"),
        "KRB5_KDC_PROFILE": os.path.join(d, "kdc.conf"),
    })
    log = open(os.path.join(d, "setup.log"), "w")

    _run(["kdb5_util", "-r", REALM, "create", "-s", "-P", "masterkey"], env, log)
    for princ, keytab in ((USER, "user.keytab"),
                          ("%s/%s" % (SERVICE, HOST), "service.keytab"),
                          ("other/%s" % HOST, "service.keytab")):
        _run(["kadmin.local", "-r", REALM, "-q", "addprinc -randkey %s" % princ],
             env, log)
        _run(["kadmin.local", "-r", REALM, "-q",
              "ktadd -k %s %s" % (os.path.join(d, keytab), princ)], env, log)

    kdc = subprocess.Popen([shutil.which("krb5kdc", path=TOOL_PATH), "-n"],
                           env=env, stdout=log, stderr=subprocess.STDOUT,
                           start_new_session=True)
    _state["kdc"] = kdc
    deadline = time.time() + 15
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError:
            if kdc.poll() is not None or time.time() > deadline:
                raise RuntimeError("krb5kdc did not start; see %s" % d)
            time.sleep(0.1)

    # Drivers inherit os.environ; the Python peer reads it too.
    os.environ.update({
        "KRB5_CONFIG": env["KRB5_CONFIG"],
        "KRB5_KTNAME": "FILE:" + os.path.join(d, "service.keytab"),
        "KRB5_CLIENT_KTNAME": "FILE:" + os.path.join(d, "user.keytab"),
        "KRB5CCNAME": "FILE:" + os.path.join(d, "ccache"),
    })
    atexit.register(_stop)


def _stop():
    kdc = _state.get("kdc")
    if kdc and kdc.poll() is None:
        os.killpg(kdc.pid, signal.SIGTERM)
        kdc.wait(timeout=5)
    if _state.get("dir") and not os.environ.get("T_KEEP_KRB5"):
        shutil.rmtree(_state["dir"], ignore_errors=True)


def require():
    """Start the realm (once), or skip the calling test if we can't."""
    if not _state["started"]:
        _state["started"] = True
        _state["skip"] = _missing()
        if not _state["skip"]:
            _start()
    if _state["skip"]:
        raise unittest.SkipTest(_state["skip"])


def principal(name):
    return "%s@%s" % (name, REALM)
