/* windlopen.c--Windows dynamic loader interface
 * Ryan Troll
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include <config.h>
#include <sasl.h>

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb,
			int (*add_plugin)(void *,void *))
{

  /* Open registry entry, and find all registered SASL libraries.
   *
   * Registry location:
   *
   *     SOFTWARE\\Carnegie Mellon\\Project Cyrus\\SASL Library\\Available Plugins
   *
   * Key - value:
   *
   *     "Cool Name" - "c:\sasl\plugins\coolname.dll"
   */

#define MAX_VALUE_NAME              128

  HKEY  hKey;
  int   Index;
  CHAR  ValueName[MAX_VALUE_NAME];
  DWORD dwcValueName = MAX_VALUE_NAME;
  CHAR  Location[MAX_PATH];
  DWORD dwcLocation = MAX_PATH;
  DWORD ret;

  /* Open the registry 
   */
  ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    SASL_KEY,
    0,
    KEY_READ,
    &hKey);

  if (ret != ERROR_SUCCESS) { return SASL_FAIL; }

  // Now enumerate across all registry keys.

  for (Index = 0; ret == ERROR_SUCCESS; Index++) {

      dwcLocation = MAX_PATH;
      dwcValueName = MAX_VALUE_NAME;
    ret= RegEnumValue (hKey, Index, ValueName, &dwcValueName,
      NULL, // Reserved,
      NULL, // Type,
      Location, &dwcLocation);

    if (ret == ERROR_SUCCESS) {

      /*
       * ValueName: "Really Cool Plugin"
       * Location: "c:\sasl\plugins\cool.dll"
       */

      HINSTANCE library    = NULL;
      FARPROC entry_point = NULL;

      /* Found a library.  Now open it.
       */
      VL(("entry is = [%s]\n", Location));


      library = LoadLibrary(Location);
      if (library == NULL) {
        DWORD foo = GetLastError();
        VL(("Unable to dlopen %s: %d\n", Location, foo));
        continue;
      }

      /* Opened the library.  Find the entrypoint
       */
      entry_point = GetProcAddress(library, entryname);
        
      if (entry_point == NULL) {
        VL(("can't get entry point %s: %d\n", entryname, GetLastError()));
        FreeLibrary(library);
        continue;
      }

      /* Opened the library, found the entrypoint.  Now add it.
       */
      if ((*add_plugin)(entry_point, (void *)library) != SASL_OK) {
        VL(("add_plugin to list failed\n"));
        FreeLibrary(library);
        continue;
      }
    }
  } /* End of registry value loop */

  RegCloseKey(hKey);

  return SASL_OK;
}






int
_sasl_done_with_plugin(void *plugin)
{
  if (! plugin)
    return SASL_BADPARAM;

  FreeLibrary((HMODULE)plugin);

  return SASL_OK;
}
