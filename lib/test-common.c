/***************************************************************************
 *
 *           Copyright 1998 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * Carnegie Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.
 * 
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL Carnegie Mellon University BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * Author: Ryan Troll <ryan+@andrew.cmu.edu>
 * 
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>
#else /* HAVE_STRINGS_H */
# include <string.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif /* HAVE_MALLOC_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/***************************************************************************
 *
 ***************************************************************************/

/* ----------------------------------------------------------------------- */

#include "test-common.h"

int test_WriteBuf(char prefix, int fd, const char *buf, unsigned buflen)
{
  char out[128];
  int ret;
  int len;

  char *base64buf;
  int base64len;

  /* Convert the data
   */
  base64len = buflen*3;
  base64buf = (char *)malloc(base64len);
  if (base64buf == NULL)
    return(0);

  to64(base64buf, buf, buflen);
  base64len = strlen(base64buf);



  /* Write the prefix 
   */
  sprintf(out, "%c: %04d ", prefix, (base64len+1));
  len = strlen(out);

  ret = write(fd, out, len);
  if (ret != len)
    return(0);

  /* And then write it
   */
  ret = write(fd, base64buf, base64len);
  if (ret != base64len)
    return(0);

  free(base64buf);
  write(fd, "\n", 1);
  return(1);  
}

int test_ReadBuf(char prefix, int fd, char **buf, unsigned *buflen)
{
  char in[128];
  char fmt[128];
  char lenbuf[5];
  int ret;

  char *base64buf;
  int base64len;

  /* Read prefix
   */
  ret = read(fd, in, 8); /* XXXXX */
  if (ret != 8) {
    fprintf(stderr, "ERROR: Reading prefix\n");
    return(0);
  }

  sprintf(fmt, "%c: %%s ", prefix); /* Generate format including prefix */

  ret = sscanf(in, fmt, &lenbuf);
  if (ret != 1) {
    printf("sscanf: returned %d (%s)\n", ret, fmt);
    return(0);
  }
  base64len = atoi(lenbuf);

  /* Read actual buffer
   */
  base64buf = (char *)malloc(base64len);
  if (base64buf == NULL) {
    fprintf(stderr, "Unable to allocate base64buf (%d bytes)\n", base64len);
    return(0);
  }

  ret = read(fd, base64buf, base64len);
  if (ret != base64len) {
    fprintf(stderr, "Unable to read %d bytes into base64 buf, read %d\n",
	    base64len, ret);
    return(0);
  }

  /* Remove added newline
   */
  base64buf[--ret] = '\0';

  /* Now convert 
   */
  *buf = (char *)malloc(base64len);
  if (*buf == NULL) {
    fprintf(stderr, "ERROR: Unable to allocate final buffer\n");
    return(0);
  }

  *buflen = from64(*buf, base64buf);
  free(base64buf);

  return(1);
}

/* base64 tables
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

void to64(out, in, inlen)
    unsigned char *out, *in;
    unsigned inlen;
{
    unsigned char oval;

    unsigned char *rawin = in;
    unsigned char *rawout = out;
    
    while (inlen >= 3) {
	*out++ = basis_64[in[0] >> 2];
	*out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
	*out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
	*out++ = basis_64[in[2] & 0x3f];
	in += 3;
	inlen -= 3;
    }
    if (inlen > 0) {
	*out++ = basis_64[in[0] >> 2];
	oval = (in[0] << 4) & 0x30;
	if (inlen > 1) oval |= in[1] >> 4;
	*out++ = basis_64[oval];
	*out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
	*out++ = '=';
    }
#if 0
    *out++ = '\r';
    *out++ = '\n';
#endif
    *out = '\0';

#if 0
fprintf(stderr, ":::  To  ::: Converted '%d:%d:%d:%d'\n",
	rawin[0], rawin[1], rawin[2], rawin[3]);
fprintf(stderr, ":::  To  ::: Into '%s'\n", rawout);
#endif

}

int from64(out, in)
    char *out, *in;
{
    int len = 0;
    int c1, c2, c3, c4;

    unsigned char *rawin = in;
    unsigned char *rawout = out;

    if (in[0] == '+' && in[1] == ' ') in += 2;
#if 0
    if (*in == '\r') return (0);
#endif
    if (*in == '\0') return (0);
    do {
	c1 = in[0];
	if (CHAR64(c1) == -1) return (-1);
	c2 = in[1];
	if (CHAR64(c2) == -1) return (-1);
	c3 = in[2];
	if (c3 != '=' && CHAR64(c3) == -1) return (-1); 
	c4 = in[3];
	if (c4 != '=' && CHAR64(c4) == -1) return (-1);
	in += 4;
	*out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
	++len;
	if (c3 != '=') {
	    *out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
	    ++len;
	    if (c4 != '=') {
		*out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
		++len;
	    }
	}
#if 0
    } while (*in != '\r' && c4 != '=');
#endif
    } while (*in != '\0' && c4 != '=');


    *out=0;

#if 0
fprintf(stderr, "::: From ::: Converted '%s'\n", rawin);
fprintf(stderr, "::: From ::: Into '%d:%d:%d:%d' (%d)\n",
	rawout[0], rawout[1], rawout[2], rawout[3], len);
#endif

    return (len);
}
