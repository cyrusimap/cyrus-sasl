// saslCRAM.cpp : Defines the entry point for the DLL application.
//
#include <config.h>

#include "stdafx.h"

#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#include "..\..\plugins\plugin_common.h"

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}

SASL_CLIENT_PLUG_INIT( crammd5 )
SASL_SERVER_PLUG_INIT( crammd5 )
