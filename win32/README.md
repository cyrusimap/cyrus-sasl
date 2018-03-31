# Microsoft Windows build scripts

*Currently supported build systems:*

* msbuild
* nmake

## msbuild

msbuild or regular Microsoft Visual Studio solutions / projects are represented as *.sln and *.vcxproj files. The solution file is capable to build release or debug version of sasl2.dll. Some plugins won't be compiled (see existing plugin*.vcxproj files), and the compiled ones will be statically linked into sasl2.dll. Even so, it's not a big deal to add support for the remaining plugins.

### Dependencies

Pay attention to cyrus-sasl.props file and its SaslDependencyRoot property. It's where it's looking for dependencies. The selection of the dependency directory was inspired by https://github.com/ShiftMediaProject, where compilation of subprojects is quite strightforward (see SMP subdirectories).

* OpenSSL (Compile from https://github.com/ShiftMediaProject/openssl. It will install everything necessary to correct directories)
* LMDB (One can try forked version https://github.com/Ri0n/lmdb till original master is fixed for Visual Studio. You will have to manually move lmdb.h and lib to dependency root directories)