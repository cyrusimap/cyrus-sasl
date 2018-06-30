from conans import ConanFile, MSBuild
from conans.tools import replace_in_file
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import conansaslbase

class CyrusSaslSasldbConan(conansaslbase.CyrusSaslBaseConan):
    name = "cyrus-sasl-saslsb"
    description = "Cyrus SASL SASLDB plugin"
    options = {"shared": [True]}
    default_options = "shared=True"
    exports_sources="../../../*"
    build_requires = "OpenSSL/1.0.2o@conan/stable"
    requires = "lmdb/0.9.22@rion/stable"

    def build(self):
        msbuild = MSBuild(self)
        msbuild.build("win32\\cyrus-sasl-sasldb.sln")

    def package(self):
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)

