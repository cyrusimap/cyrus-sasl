# Define the minimal Windows OS you want to run on:40 (NT), 50 (W2K), 51 (XP)
# Default is no restrictions. Currently we only check for 51 or later.
#TARGET_WIN_SYSTEM=51

!IF "$(TARGET_WIN_SYSTEM)" == ""
!MESSAGE Applications and libraries should run on any Win32 system.
TARGET_WIN_SYSTEM=0
!ENDIF

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

