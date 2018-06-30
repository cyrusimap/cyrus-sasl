from conans import ConanFile

class CyrusSaslBaseConan(ConanFile):
    version = "2.1.26"
    license = "BSD-with-attribution"
    url = "https://github.com/Ri0n/cyrus-sasl.git"
    settings = "os", "compiler", "build_type", "arch"
    exports_sources="../../../*"
