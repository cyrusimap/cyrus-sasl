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
#ifndef __hpux
#include <dlfcn.h>
#endif /* !__hpux */
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

#ifdef __hpux
#include <dl.h>

typedef shl_t dll_handle;
typedef void * dll_func;

dll_handle
dlopen(char *fname, int mode)
{
    shl_t h = shl_load(fname, BIND_DEFERRED, 0L);
    shl_t *hp = NULL;
    
    if (h) {
	hp = (shl_t *)malloc(sizeof (shl_t));
	if (!hp) {
	    shl_unload(h);
	} else {
	    *hp = h;
	}
    }

    return (dll_handle)hp;
}

int
dlclose(dll_handle h)
{
    shl_t hp = *((shl_t *)h);
    if (hp != NULL) free(hp);
    return shl_unload(h);
}

dll_func
dlsym(dll_handle h, char *n)
{
    dll_func handle;
    
    if (shl_findsym ((shl_t *)h, n, TYPE_PROCEDURE, &handle))
	return NULL;
    
    return (dll_func)handle;
}

char *dlerror()
{
    if (errno != 0) {
	return strerror(errno);
    }
    return "Generic shared library error";
}

#define SO_SUFFIX	".sl"
#else /* __hpux */
#define SO_SUFFIX	".so"
#endif /* __hpux */


/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb,
			const sasl_callback_t *verifyfile_cb,
			int (*add_plugin)(void *,void *))
{
  /* XXX These fixed-length buffers could be a problem;
   * this really needs to be rewritten to do overflow
   * checks appropriately. */
  int result;
  char str[PATH_MAX], tmp[PATH_MAX], c, prefix[PATH_MAX];
#if __OpenBSD__
  char adj_entryname[1024];
#else
#define adj_entryname entryname
#endif
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
      || ! verifyfile_cb
      || verifyfile_cb->id != SASL_CB_VERIFYFILE
      || ! verifyfile_cb->proc
      || ! add_plugin)
    return SASL_BADPARAM;

#if __OpenBSD__
  snprintf(adj_entryname, sizeof adj_entryname, "_%s", entryname);
#endif

  /* get the path to the plugins */
  result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
						  &path);
  result = SASL_OK;

  if (result != SASL_OK)
    return result;

  if (! path) {
    free_path = 0;
    path = PLUGINDIR;
  } else {
    free_path = 1;
  }

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
	char name[PATH_MAX];
	int flag;


	length = NAMLEN(dir);
	if (length < 4) continue; /* can not possibly be what we're looking for */

	if (length + pos>=PATH_MAX) continue; /* too big */

	if (strcmp(dir->d_name + (length - 3), SO_SUFFIX)) continue;

	memcpy(name,dir->d_name,length);
	name[length]='\0';
	
	strcpy(tmp,prefix);
	strcat(tmp,name);
	
	VL(("entry is = [%s]\n",tmp));
	
	/* Ask the application if we should use this file or not */
	result = ((sasl_verifyfile_t *)(verifyfile_cb->proc))
	    (verifyfile_cb->context, tmp);
	/* returns continue if this file is to be skipped */
	if (result == SASL_CONTINUE) continue; 
	
	if (result != SASL_OK) return result;
	
#ifdef RTLD_NOW
	flag = RTLD_NOW;
#else
	flag = 0;
#endif
	if (!(library = dlopen(tmp, flag))) {
	    _sasl_log(NULL, SASL_LOG_ERR, NULL, 0, 0,
		      "unable to dlopen %s: %s", tmp, dlerror());
	    continue;
	}
	entry_point = NULL;
	entry_point = dlsym(library, adj_entryname);

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
	VL(("added [%s] successfully\n",dir->d_name));
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
