/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.c,v 1.2 2001/12/04 02:06:49 rjs3 Exp $
 */
/* 
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#ifndef macintosh
#ifdef WIN32
# include <winsock.h>
#else
# include <sys/param.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /* WIN32 */
#endif /* macintosh */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#include <errno.h>
#include <ctype.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "plugin_common.h"

/* translate IPv4 mapped IPv6 address to IPv4 address */
static void sockaddr_unmapped(
#ifdef IN6_IS_ADDR_V4MAPPED
  struct sockaddr *sa, socklen_t *len
#else
  struct sockaddr *sa __attribute__((unused)),
  socklen_t *len __attribute__((unused))
#endif
)
{
#ifdef IN6_IS_ADDR_V4MAPPED
    struct sockaddr_in6 *sin6;
    struct sockaddr_in *sin4;
    uint32_t addr;
    int port;

    if (sa->sa_family != AF_INET6)
	return;
    sin6 = (struct sockaddr_in6 *)sa;
    if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
	return;
    sin4 = (struct sockaddr_in *)sa;
    addr = *(uint32_t *)&sin6->sin6_addr.s6_addr[12];
    port = sin6->sin6_port;
    memset(sin4, 0, sizeof(struct sockaddr_in));
    sin4->sin_addr.s_addr = addr;
    sin4->sin_port = port;
    sin4->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
    sin4->sin_len = sizeof(struct sockaddr_in);
#endif
    *len = sizeof(struct sockaddr_in);
#else
    return;
#endif
}

int _plug_ipfromstring(const sasl_utils_t *utils, const char *addr,
		       struct sockaddr *out, socklen_t outlen) 
{
    int i, j;
    socklen_t len;
    struct sockaddr_storage ss;
    struct addrinfo hints, *ai = NULL;
    char hbuf[NI_MAXHOST];
    
    if(!utils || !addr || !out) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    /* Parse the address */
    for (i = 0; addr[i] != '\0' && addr[i] != ';'; i++) {
	if (i >= NI_MAXHOST) {
	    if(utils) PARAMERROR( utils );
	    return SASL_BADPARAM;
	}
	hbuf[i] = addr[i];
    }
    hbuf[i] = '\0';

    if (addr[i] == ';')
	i++;
    /* XXX/FIXME: Do we need this check? */
    for (j = i; addr[j] != '\0'; j++)
	if (!isdigit((int)(addr[j]))) {
	    PARAMERROR( utils );
	    return SASL_BADPARAM;
	}

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    if (getaddrinfo(hbuf, &addr[i], &hints, &ai) != 0) {	
	PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    len = ai->ai_addrlen;
    memcpy(&ss, ai->ai_addr, len);
    freeaddrinfo(ai);
    sockaddr_unmapped((struct sockaddr *)&ss, &len);
    if (outlen < len) {
	PARAMERROR( utils );
	return SASL_BUFOVER;
    }

    memcpy(out, &ss, len);

    return SASL_OK;
}

int _plug_iovec_to_buf(const sasl_utils_t *utils, const struct iovec *vec,
		       unsigned numiov, buffer_info_t **output) 
{
    unsigned i;
    int ret;
    buffer_info_t *out;
    char *pos;

    if(!utils || !vec || !output) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }
    
    if(!(*output)) {
	*output = utils->malloc(sizeof(buffer_info_t));
	if(!*output) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	memset(*output,0,sizeof(buffer_info_t));
    }

    out = *output;
    
    out->curlen = 0;
    for(i=0; i<numiov; i++)
	out->curlen += vec[i].iov_len;

    ret = _plug_buf_alloc(utils, &out->data, &out->reallen, out->curlen);

    if(ret != SASL_OK) {
	MEMERROR(utils);
	return SASL_NOMEM;
    }
    
    memset(out->data, 0, out->reallen);
    pos = out->data;
    
    for(i=0; i<numiov; i++) {
	memcpy(pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}

/* Basically a conditional call to realloc(), if we need more */
int _plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
		    unsigned *curlen, unsigned newlen) 
{
    if(!utils || !rwbuf || !curlen) {
	PARAMERROR(utils);
	return SASL_BADPARAM;
    }

    if(!(*rwbuf)) {
	*rwbuf = utils->malloc(newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	size_t needed = 2*(*curlen);

	while(needed < newlen)
	    needed *= 2;

	*rwbuf = utils->realloc(*rwbuf, needed);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = needed;
    } 

    return SASL_OK;
}

/* copy a string */
int _plug_strdup(const sasl_utils_t * utils, const char *in,
		 char **out, int *outlen)
{
  size_t len = strlen(in);

  if(!utils || !in || !out) {
      if(utils) PARAMERROR(utils);
      return SASL_BADPARAM;
  }

  *out = utils->malloc(len + 1);
  if (!*out) {
      MEMERROR(utils);
      return SASL_NOMEM;
  }

  strcpy((char *) *out, in);

  if (outlen)
      *outlen = len;

  return SASL_OK;
}

void _plug_free_string(const sasl_utils_t *utils, char **str)
{
  size_t len;

  if (!utils || !str || !(*str)) return;

  len = strlen(*str);

  utils->erasebuffer(*str, len);
  utils->free(*str);

  *str=NULL;
}

void _plug_free_secret(const sasl_utils_t *utils, sasl_secret_t **secret) 
{
    if(!utils || !secret || !(*secret)) return;

    utils->erasebuffer((*secret)->data, (*secret)->len);
    utils->free(*secret);
    *secret = NULL;
}
