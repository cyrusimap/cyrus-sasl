!IF "$(CFG)" == ""
CFG=Release
!MESSAGE No configuration specified. Defaulting to $(CFG).
!ENDIF 

!IF "$(STATIC)" != "yes"
STATIC=no
!MESSAGE Using MSVCRT.dll as C library by default.
!ENDIF 

!IF "$(DB_LIB)" == ""
DB_LIB=libdb41s.lib
!MESSAGE Defaulting SleepyCat library name to $(DB_LIB).
!ENDIF

!IF "$(DB_INCLUDE)" == ""
DB_INCLUDE=c:\work\isode\db\build_win32
!MESSAGE Defaulting SleepyCat include path to $(DB_INCLUDE).
!ENDIF

!IF "$(DB_LIBPATH)" == ""
DB_LIBPATH=c:\work\isode\db\build_win32\Release_static
!MESSAGE Defaulting SleepyCat library path to $(DB_LIBPATH).
!ENDIF

