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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#if STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(), *strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif
#include <dlfcn.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include "sasl.h"
#include "saslint.h"

#if HAVE_DIRENT_H 
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct 
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif 
#endif 

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
#  define PATH_MAX _POSIX_PATH_MAX
# else
#  define PATH_MAX 1024		/* arbitrary; probably big enough */
# endif
#endif

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			int (*add_plugin)(void *,void *))
{
  /* XXX These fixed-length buffers could be a problem;
   * this really needs to be rewritten to do overflow
   * checks appropriately. */
  char str[PATH_MAX],tmp[PATH_MAX],c,prefix[PATH_MAX];
  int pos;
  char *path=NULL;
  int position;
  DIR *dp;
  struct dirent *dir;

  path=getenv(SASL_PATH_ENV_VAR);

  if (path==NULL)
    path=PLUGINDIR;

  if (strlen(path)>=PATH_MAX) /* no you can't buffer overrun */
    return SASL_FAIL;

  position=0;
  do {
    pos=0;
    do {
      c=path[position];
      position++;
      str[pos]=c;
      pos++;
    } while ((c!=':') && (c!='=') && (c!=0));
    str[pos-1]=0;

    strcpy(prefix,str);
    strcat(prefix,"/");
    
    if ((dp=opendir(str)) !=NULL) /* ignore errors */    
    {
      strcat(str, "/");
      while ((dir=readdir(dp)) != NULL)
      {
	size_t length;
	void *library;
	void *entry_point;

	length = NAMLEN(dir);
	if (length < 4) continue;
	if (strcmp(dir->d_name + (length - 3), ".so")) continue;
	{
	  char name[PATH_MAX];
	  memcpy(name,dir->d_name,length);
	  name[length]=0;

	  strcpy(tmp,prefix);
	  strcat(tmp,name);

	  VL(("entry is = [%s]\n",tmp));

	  library=NULL;
	  if (!(library=dlopen(tmp,RTLD_LAZY)))
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
