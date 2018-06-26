from conans import ConanFile

class CyrusSaslBaseConan(ConanFile):
    version = "2.1.26"
    license = "BSD-with-attribution"
    url = "https://github.com/Ri0n/cyrus-sasl.git"
    settings = "os", "compiler", "build_type", "arch"
    exports_sources="../../../*"
    requires = "OpenSSL/1.0.2o@conan/stable" #, "lmdb/0.9.22@rion/stable", "krb5-gssapi/1.16.1@rion/stable"