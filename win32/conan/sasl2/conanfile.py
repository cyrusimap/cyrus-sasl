from conans import ConanFile, MSBuild
from conans.tools import replace_in_file
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import conansaslbase

class CyrusSaslConan(conansaslbase.CyrusSaslBaseConan):
    name = "cyrus-sasl"
    version = "2.1.26"
    license = "BSD-with-attribution"
    url = "https://github.com/Ri0n/cyrus-sasl.git"
    description = "Simple Authentication and Security Layer (SASL)"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = "shared=True"
    #generators = "visual_studio"
    exports_sources="../../../*"
    requires = "OpenSSL/1.0.2o@conan/stable" #, "lmdb/0.9.22@rion/stable", "krb5-gssapi/1.16.1@rion/stable"

    def build(self):
        msbuild = MSBuild(self)
        msbuild.build("win32\\cyrus-sasl-core.sln")

    def package(self):
        self.copy("*.h", dst="include\sasl", src="include")
        self.copy("*sasl2*.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["sasl2.lib"]

