from conans import ConanFile, MSBuild
from conans.tools import replace_in_file

# This is a common library used in every other subproject of cyrus-sasl
# Even though cyrus-sasl-core.sln builds its own copy of this library
# making it possible to build static cyrus-sasl while this one is 
# supposed to be used nly with dynamic runtimes (for dynamic plugins).
class CyrusSaslCommonConan(ConanFile):
    name = "cyrus-sasl-common"
    version = "2.1.26"
    license = "BSD-with-attribution"
    url = "https://github.com/Ri0n/cyrus-sasl.git"
    description = "Cyrus SASL internal common library"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [False]}
    default_options = "shared=False"
    generators = "visual_studio"
    exports_sources="../../../*"
    requires = "OpenSSL/1.0.2o@conan/stable"

    def build(self):
        #replace_in_file("win32\\openssl.props", "libeay32.lib;", "")
        msbuild = MSBuild(self)
        msbuild.build_env.runtime = ["MD","MDd"][self.settings.get_safe("build_type") == "Debug"]
        msbuild.build("win32\\cyrus-sasl-common.sln")

    def package(self):
        self.copy("*common*.lib", dst="lib", keep_path=False)
        self.copy("*common*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["libcommon.lib"]

