/* dlopen.c--Unix dlopen() dynamic loader interface
 * Rob Earhart
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
#include <dlfcn.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <sasl.h>
#include "saslint.h"

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
#  define PATH_MAX _POSIX_PATH_MAX
# else
#  define PATH_MAX 1024		/* arbitrary; probably big enough will
				 * probably only be 256+64 on
				 * pre-posix machines */
# endif
#endif

#ifndef NAME_MAX
# ifdef _POSIX_NAME_MAX
#  define NAME_MAX _POSIX_NAME_MAX
# else
#  define NAME_MAX 16
# endif
#endif
 
#if NAME_MAX < 8
#  define NAME_MAX 8
#endif

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb,
			int (*add_plugin)(void *,void *))
{
  /* XXX These fixed-length buffers could be a problem;
   * this really needs to be rewritten to do overflow
   * checks appropriately. */
  int result;
  char str[PATH_MAX],tmp[PATH_MAX],c,prefix[PATH_MAX];
  int pos;
  char *path=NULL;
  int free_path;
  int position;
  DIR *dp;
  struct dirent *dir;

  if (! entryname
      || ! getpath_cb
      || getpath_cb->id != SASL_CB_GETPATH
      || ! getpath_cb->proc
      || ! add_plugin)
    return SASL_BADPARAM;

  result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
						  &path);

  if (result != SASL_OK)
    return result;

  if (! path) {
    free_path = 0;
    path = PLUGINDIR;
  } else
    free_path = 1;
  /* xxx sendmail guys -NAME_MAX */
  if (strlen(path)>=PATH_MAX) { /* no you can't buffer overrun */
    if (free_path)
      sasl_FREE(path);
    return SASL_FAIL;
  }

  position=0;
  do {
    pos=0;
    do {
      c=path[position];
      position++;
      str[pos]=c;
      pos++;
    } while ((c!=':') && (c!='=') && (c!=0));
    str[pos-1]='\0';

    strcpy(prefix,str);
    strcat(prefix,"/");

    if ((dp=opendir(str)) !=NULL) /* ignore errors */    
    {
      while ((dir=readdir(dp)) != NULL)
      {
	size_t length;
	void *library;
	void *entry_point;

	length = NAMLEN(dir);
	if (length < 4) continue; /* can not possibly be what we're looking for */

	if (length + pos>=PATH_MAX) continue; /* too big */

	if (strcmp(dir->d_name + (length - 3), ".so")) continue;
	{
	  char name[PATH_MAX];
	  memcpy(name,dir->d_name,length);
	  name[length]='\0';

	  strcpy(tmp,prefix);
	  strcat(tmp,name);

	  VL(("entry is = [%s]\n",tmp));

	  library=NULL;
	  if (!(library=dlopen(tmp,RTLD_NOW))) /* xxx no RTLD_LOCAL | on linux */
	    {
	      VL(("Unable to dlopen %s: %s\n", tmp, dlerror()));
	      continue;
	    }
	}
	entry_point=NULL;
	entry_point = dlsym(library, entryname);


	if (entry_point == NULL) {
	  VL(("can't get an entry point\n"));
	  dlclose(library);
	  continue;
	}

	if ((*add_plugin)(entry_point, library) != SASL_OK) {
	  VL(("add_plugin to list failed\n"));
	  dlclose(library);
	  continue;
	}
	VL(("added [%s] sucessfully\n",dir->d_name));
      }

     closedir(dp);
    }

  } while ((c!='=') && (c!=0));

  if (free_path)
    sasl_FREE(path);

  return SASL_OK;
}

int
_sasl_done_with_plugin(void *plugin)
{
  if (! plugin)
    return SASL_BADPARAM;

  dlclose(plugin);

  return SASL_OK;
}
