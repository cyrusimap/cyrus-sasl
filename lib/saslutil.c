/* saslutil.c
 * Tim Martin 5/20/98
 * $Id: saslutil.c,v 1.5 1998/11/20 16:22:00 ryan Exp $
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
#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
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
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"

/*  Contains:
 *
 * sasl_encode64
 * sasl_decode64 
 * sasl_utf8verify
 * sasl_randcreate
 * sasl_randfree
 * sasl_randseed
 * sasl_rand
 * sasl_churn
*/

char *encode_table;
char *decode_table;

struct sasl_rand_s {
  unsigned short int pool[3];
};

#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";

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


int sasl_encode64(const unsigned char *in, int inlen,
	       unsigned char *out, int outmax, int *outlen)
{
    unsigned char oval;
    char *blah;

    blah=(char *) out;
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
    *out = '\0';

    return SASL_OK;
}


int sasl_decode64(const char *in,int inlen, char *out,int *outlen)
{
    int len = 0,lup;
    int c1, c2, c3, c4;

    if (in[0] == '+' && in[1] == ' ') in += 2;
    if (*in == '\r') return (0);

    for (lup=0;lup<inlen/4;lup++)
    {
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
    }

    *outlen=len;

    return SASL_OK;
}





  /* borrowed from larry. probably works :)
   * probably is also in acap server somewhere
   */
int sasl_utf8verify(const char *str, int len)
{
  int i;
  for (i = 0; i < len; i++) {
    /* how many octets? */
    int seqlen = 0;
    while (str[i] & (0x80 >> seqlen)) ++seqlen;
    if (seqlen == 0) continue; /* this is a valid US-ASCII char */
    if (seqlen == 1) return SASL_BADPROT; /* this shouldn't happen here */
    if (seqlen > 6) return SASL_BADPROT; /* illegal */
    while (--seqlen)
      if ((str[++i] & 0xC0) != 0xF0) return SASL_BADPROT; /* needed a 10 octet */
  }
  return SASL_OK;
}      

int parityof(unsigned char ch)
{
  int ret=0;
  int lup;
  for (lup=0;lup<8;lup++)
    ret+= (ch >> lup) & 1;

  return ret;
}

static unsigned short* getranddata()
{
  unsigned short *ret;
  unsigned char *tmp;
  long curtime;
  FILE *f;

  ret=sasl_ALLOC(6);
  if (ret ==NULL) return NULL;
  memset(ret,0,6);

  if ((f=fopen("/dev/random","r"))!=NULL)
  {    
    fread(ret, 1, 6, f);

    fclose(f);
    return ret;
  }
  
  if ((f=fopen("/dev/audio","r"))!=NULL)
  {
    int parity=0,lup,lup2;     
    tmp=sasl_ALLOC(200);
    if (tmp ==NULL) return NULL;      

    for (lup=0;lup<48;lup++)
    {

      fread(tmp, 1, 200, f);
      parity=0;
      /* get the parity */
      for (lup2=0;lup2<200;lup2++)
	parity+=parityof(tmp[lup2]);

      ret[lup/16] = ret[lup/16] & ( parity << (lup%16));
    }
    memset(tmp, 0, 200);
    sasl_FREE((tmp));    
    fclose(f);
    return ret;
  }

  /* if all else fails just use timer */
  curtime=(long) time(NULL);

  ret[0]=(unsigned short) (curtime >> 16);
  ret[1]=(unsigned short) (curtime & 0x0000FFFF);
  ret[2]=(unsigned short) ((curtime*7) >> 5);

  return ret;

}

int sasl_randcreate(sasl_rand_t **rpool)
{
  unsigned short *data;
  (*rpool)=sasl_ALLOC(sizeof(sasl_rand_t));
  if ((*rpool) ==NULL) return SASL_NOMEM;

  data=getranddata();
  if (data==NULL)
    return SASL_FAIL;

  memcpy((*rpool)->pool, data, 6);

  memset(data, 0, 6); /* wipe it out */
  sasl_FREE((data));
  return SASL_OK;
}

void sasl_randfree(sasl_rand_t **rpool)
{
  sasl_FREE((*rpool));
}

void sasl_randseed (sasl_rand_t *rpool, const char *seed, int len)
{
  /* is it acceptable to just use the 1st 3 char's given??? */
  int lup;
  
  for (lup=0;lup<3;lup++)
    if (len>lup)
      rpool->pool[lup]=seed[lup];
}

void sasl_rand (sasl_rand_t *rpool, char *buf, int len)
{
  int lup;
  if (buf==NULL) return;

#ifdef WIN32
  for (lup=0;lup<len;lup++)
    buf[lup]= (char) (rand());
#else /* WIN32 */
  for (lup=0;lup<len;lup++)
    buf[lup]= (char) jrand48(rpool->pool);
#endif /* WIN32 */
}

void sasl_churn (sasl_rand_t *rpool, const char *data, int len)
{
  int lup,spot;
  spot=0;

  for (lup=0;lup<len;lup++)
  {
    rpool->pool[spot]+=data[lup];
    spot++;
    if (spot==3)
      spot=0;
  }

}
