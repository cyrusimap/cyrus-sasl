/* dlopen.c--Unix dlopen() dynamic loader interface
 * Rob Earhart
 */

/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#ifndef __hpux
#include <dlfcn.h>
#endif /* !__hpux */
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <sasl.h>
#include "saslint.h"

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* HAVE_DIRENT_H */
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
#endif /* ! HAVE_DIRENT_H */

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

/* loads a single mechanism */
int _sasl_get_plugin(const char *file,
		     const char *entryname,
		     const sasl_callback_t *verifyfile_cb,
		     void **entrypointptr,
		     void **libraryptr)
{
    int r = 0;
    int flag;
    void *library;
    void *entry_point;
#if __OpenBSD__
    char adj_entryname[1024];
#else
#define adj_entryname entryname
#endif

    r = ((sasl_verifyfile_t *)(verifyfile_cb->proc))
		    (verifyfile_cb->context, file, SASL_VRFY_PLUGIN);
    if (r != SASL_OK) return r;

#ifdef RTLD_NOW
    flag = RTLD_NOW;
#else
    flag = 0;
#endif
    if (!(library = dlopen(file, flag))) {
	_sasl_log(NULL, SASL_LOG_ERR, NULL, 0, 0,
		  "unable to dlopen %s: %s", file, dlerror());
	return SASL_FAIL;
    }

#if __OpenBSD__
    snprintf(adj_entryname, sizeof adj_entryname, "_%s", entryname);
#endif

    entry_point = NULL;
    entry_point = dlsym(library, adj_entryname);
    if (entry_point == NULL) {
	_sasl_log(NULL, SASL_LOG_ERR, NULL, 0, 0,
		  "unable to get entry point %s in %s: %s", adj_entryname,
		  file, dlerror());
	return SASL_FAIL;
    }

    *entrypointptr = entry_point;
    *libraryptr = library;
    return SASL_OK;
}

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb,
			const sasl_callback_t *verifyfile_cb,
			int (*add_plugin)(void *,void *))
{
    int result;
    char str[PATH_MAX], tmp[PATH_MAX+2], prefix[PATH_MAX+2];
				/* 1 for '/' 1 for trailing '\0' */
    char c;
    int pos;
    char *path=NULL;
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

    /* get the path to the plugins */
    result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
						    &path);
    if (result != SASL_OK) return result;
    if (! path) return SASL_FAIL;

    if (strlen(path) >= PATH_MAX) { /* no you can't buffer overrun */
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

		length = NAMLEN(dir);
		if (length < 4) 
		    continue; /* can not possibly be what we're looking for */

		if (length + pos>=PATH_MAX) continue; /* too big */

		if (strcmp(dir->d_name + (length - 3), SO_SUFFIX)) continue;

		memcpy(name,dir->d_name,length);
		name[length]='\0';
	
		strcpy(tmp,prefix);
		strcat(tmp,name);
	
		result = _sasl_get_plugin(tmp, entryname,
					  verifyfile_cb,
					  &entry_point, &library);

		if (result == SASL_OK) {
		    result = (*add_plugin)(entry_point, library);
		    if (result != SASL_OK) {
			_sasl_log(NULL, SASL_LOG_ERR, NULL, result, 0,
				  "add_plugin(%s) failed: %z", tmp);
			dlclose(library);
			continue;
		    }
		}

		/* added successfully */
	    }

	    closedir(dp);
	}

    } while ((c!='=') && (c!=0));

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
