# Microsoft Windows build scripts

**Currently supported build systems:**

* msbuild
* nmake

## msbuild

msbuild or regular Microsoft Visual Studio solutions / projects are represented as 
\*.sln and \*.vcxproj files. The solution file is capable to build release or debug 
version of sasl2.dll. Some plugins won't be compiled (see existing plugin*.vcxproj files),
and the compiled ones will be statically linked into sasl2.dll.
Even so, it's not a big deal to add support for the remaining plugins.

**IMPORTANT:** Only x64 configuration was tested with current Visual Studio projects.

#### Dependencies

Pay attention to cyrus-sasl.props file and its SaslDependencyRoot property. 
It's where it's looking for dependencies.

* **OpenSSL** (Compile from https://github.com/psi-im/openssl-vs. 
 It will install everything necessary to correct directories. Otherwise just copy openssl
 headers ssl.lib, crypto.lib or their debug versions with **d** suffix to SaslDependencyRoot.
 Note, cyrus-sasl solution by default uses /MD or /MDd switches. So ensure it's the same for OpenSSL)
* **LMDB** (One can try forked version https://github.com/Ri0n/lmdb till original master
 is fixed for Visual Studio. . But you can just disable sasldb subproject.)
* **MIT Kerberos for Windows** (http://web.mit.edu/kerberos/dist/index.html select full install.
  required only for gssapiv2 plugin which may be disabled if not needed)

#### Compilation

* Open the solution in Visual Studio
* Edit "User Macros" in Property Manager -> cyrus-sasl if defaults are not Ok.
* For Debug version, follow https://msdn.microsoft.com/en-us/library/x54fht41(v=vs.85).aspx 
  to add dependency libs directory (this is a subject for further improvements to the solution).
* If you don't need sasldb, then follow https://msdn.microsoft.com/en-us/library/jj676765.aspx to
  exclude from build sasldb and plugin_sasldb projects
* Finally build the solution

#### Questions

The Visual Studio solution, project files and property sheets were written by [Sergey Ilinykh](mailto:rion4ik@gmail.com).
Feel free to mail and ask questions.

## nmake

TBD

nmake makefiles weren't updated for awhile and most likely won't build.