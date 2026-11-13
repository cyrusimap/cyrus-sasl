# Microsoft Windows build scripts

**Currently supported build systems:**

* msbuild
* nmake

## msbuild

msbuild or regular Microsoft Visual Studio solutions / projects are represented as 
\*.sln and \*.vcxproj files. The solution file is capable to build release or debug 
version of sasl2.dll. Sasl plugins are splitted into two sets. Some of them will be
statically linked into sasl2.dll and others have separate solution files. This is 
done to simplify configuration and compilation with 3rdparty tools like Conan
package manager. And there are some plugins which won't be compiled at all at the
moment but may be support for them will be added later.

There are 3 solution files:

* **core** builds sasl2.dll with some static plugins included.
* **sasldb** builds sasldb library and corresponding dynamic plugin
* **gssapi** builds gssapi dynamic plugin

**IMPORTANT:** Only x64 configuration was tested with current Visual Studio projects.

#### Dependencies

Pay attention to cyrus-sasl.props file and its SaslDependencyRoot property. 
It's where it's looking for dependencies. You can put your OpenSSL installation in there as well
as any other dependency. Just make sure it's exacty in "lib" and "include" directories to make
it compile

By default the **core** solution depends on OpenSSL. You can change openssl.props file if putting
OpenSSL into SaslDependencyRoot is not an option for you. In this case openssl.props may look 
something like this

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ImportGroup Label="PropertySheets" />
  <PropertyGroup Label="UserMacros" />
  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>C:\path\to\openssl\install\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
    </ClCompile>
    <Link>
      <AdditionalLibraryDirectories>C:\path\to\openssl\install\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
      <AdditionalDependencies>libeay32.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup />
</Project>
```
When using OpenSSL, point to its correct library name (see libeay32.lib).
Also make sure previous values are preserved by including `%(something)` as in the example above.

---

**sasldb** solution depends on [LMDB](https://github.com/LMDB/lmdb) library. Again you can
play with cyrus-sasl.props and its SaslDependencyRoot or just change paths and libs to 
whatever you want in [sasldb.props](sasldb.props). If the version from upstream repository doesn't build
for you (even from stable branches), you can try next fork https://github.com/Ri0n/lmdb

---

**gssapiv2** plugin depends on one of Kerberos realization. But only MIT Kerberos was tested with msbuild.
As always put dependencies to the location pointed by cyrus-sasl.props or change gssapiv2 project file.

#### Cryptographic backend

OpenSSL remains the default. Set `/p:SaslCryptoBackend=cng` to use native
Windows CNG instead, or `/p:SaslCryptoBackend=callbacks` to require an
application-supplied `SASL_CB_CRYPTO` callback. CNG requires Windows 10 or
later and a Windows 10 SDK. It supports MD5 and SHA-1/256/384/512; SHA-224
is not provided. OTP and SRP still require OpenSSL. Other mechanisms keep
their own dependencies.

`sample_cng_client.vcxproj` demonstrates application crypto callbacks using
CNG, including with a callbacks-only core. `test_cng.vcxproj` builds the CNG
known-answer, streaming and concurrency tests. Both are optional projects.
See the [programming guide](../docsrc/sasl/developer/programming.rst) for
build commands, backend scope and channel-binding requirements.

#### Compilation

Basically there 3 ways to compile with msbuild.

1. Just open any of solution files in Visual Studio and build it (assuming the dependency are
   already in correct locations)
2. Use msbuild command line util (pretty much the same as 1 but from command line)
3. Use [Conan package manager](https://conan.io) (will download dependencies from a cloud and build just cyrus-sasl.
   Or after the sources will be built automatically on CI, so one can just download binaries)

Regarding solution files there are to options:

1. cyrus-sasl-all-in-one.sln builds everything and depends on everything
2. cyrus-sasl-*.sln (other sln files) build something specific.
  * cyrus-sasl-core.sln builds sasl2 library with some static plugins included
  * cyrus-sasl-common.sln builds just common library useful for plugins development
  * cyrus-sasl-sasldb.sln builds sasldb library and corresponding plugin
  * cyrus-sasl-gssapiv2.sln builds gssapiv2 plugin

Build with Conan is not that hard too. I need it installed and added to PATH,
then from console in one of win32\conan subdirectory try something like

```cmd
> conan create . yourname/stable
```
For more information about Conan please read their
[documentation](https://docs.conan.io/en/latest)

#### Questions

The Visual Studio solution, project files and property sheets were
written by [Sergey Ilinykh](mailto:rion4ik@gmail.com).
Feel free to mail and ask questions.

## nmake

The core, SCRAM plugin and callback sample support `SASL_CRYPTO=openssl`,
`SASL_CRYPTO=callbacks`, or `SASL_CRYPTO=cng`. Clean before changing modes.
As with MSBuild, CNG needs Windows 10 or later and a Windows 10 SDK.

Generate plugin entry points first by running `powershell -File makeinit.ps1`
from `win32`. For a minimal native CNG build, run these commands from a
Visual Studio developer command prompt in the source root:

```cmd
cd lib
nmake /f NTMakefile SASL_CRYPTO=cng libsasl.dll
cd ..\plugins
nmake /f NTMakefile SASL_CRYPTO=cng saslSCRAM.dll
cd ..\sample
nmake /f NTMakefile SASL_CRYPTO=cng sample-cng-client.exe
```

Keep `libsasl.dll` on the executable search path and make the SCRAM module
available through the application's SASL plugin search path. The sample's
`-p` option selects a plugin directory. Other optional NMake targets retain
their own dependencies; they are not required for this minimal build.