from conans import ConanFile, MSBuild
from conans.tools import replace_in_file
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import conansaslbase

class CyrusSaslGssapi2Conan(conansaslbase.CyrusSaslBaseConan):
    name = "cyrus-sasl-gssapiv2"
    version = "2.1.26"
    license = "BSD-with-attribution"
    url = "https://github.com/Ri0n/cyrus-sasl.git"
    description = "Cyrus SASL GSSAPIv2 plugin"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True]}
    default_options = "shared=True"
    #generators = "visual_studio"
    exports_sources="../../../*"
    #build_requires = "cyrus-sasl-common/2.1.26@rion/stable"
    build_requires = "OpenSSL/1.0.2o@conan/stable"
    requires = "krb5-gssapi/1.16.1@rion/stable"

    def build(self):
        msbuild = MSBuild(self)
        msbuild.build("win32\\cyrus-sasl-gssapiv2.sln")

    def package(self):
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        
    #def package_info(self):
    #    self.cpp_info.libs = ["sasl2.lib"]

