/* saslutil.c
 * Tim Martin 5/20/98
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
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "saslint.h"
#include <saslutil.h>

/*  Contains:
 *
 * sasl_decode64 
 * sasl_encode64
 * sasl_mkchal
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
  int initialized; /* since the init time might be really bad let's make this lazy */
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

/* base64 encode
 *  in      -- input data
 *  inlen   -- input data length
 *  out     -- output buffer (will be NUL terminated)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen  -- gets actual length of output buffer (optional)
 * 
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */

int sasl_encode64(const char *_in, unsigned inlen,
		  char *_out, unsigned outmax, unsigned *outlen)
{
    const unsigned char *in = (const unsigned char *)_in;
    unsigned char *out = (unsigned char *)_out;
    unsigned char oval;
    char *blah;
    unsigned olen;

    /* Will it fit? */
    olen = (inlen + 2) / 3 * 4;
    if (outlen)
      *outlen = olen;
    if (outmax < olen)
      return SASL_BUFOVER;

    /* Do the work... */
    blah=(char *) out;
    while (inlen >= 3) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = basis_64[in[2] & 0x3f];
        in += 3;
        inlen -= 3;
    }
    if (inlen > 0) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        oval = (in[0] << 4) & 0x30;
        if (inlen > 1) oval |= in[1] >> 4;
        *out++ = basis_64[oval];
        *out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }

    if (olen < outmax)
      *out = '\0';
    
    return SASL_OK;
}

/* base64 decode
 *  in     -- input data
 *  inlen  -- length of input data
 *  out    -- output data (may be same as in, must have enough space)
 * result:
 *  outlen -- actual output length
 *
 * returns SASL_BADPROT on bad base64, SASL_OK on success
 */

int sasl_decode64(const char *in, unsigned inlen,
		  char *out, unsigned *outlen)
{
    unsigned len = 0,lup;
    int c1, c2, c3, c4;

    /* check parameters */
    if (out==NULL) return SASL_FAIL;

    /* xxx these necessary? */
    if (in[0] == '+' && in[1] == ' ') in += 2;
    if (*in == '\r') return SASL_FAIL;

    for (lup=0;lup<inlen/4;lup++)
    {
        c1 = in[0];
        if (CHAR64(c1) == -1) return SASL_FAIL;
        c2 = in[1];
        if (CHAR64(c2) == -1) return SASL_FAIL;
        c3 = in[2];
        if (c3 != '=' && CHAR64(c3) == -1) return SASL_FAIL; 
        c4 = in[3];
        if (c4 != '=' && CHAR64(c4) == -1) return SASL_FAIL;
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

    *out=0; /* terminate string */

    *outlen=len;

    return SASL_OK;
}

/* make a challenge string (NUL terminated)
 *  buf      -- buffer for result
 *  maxlen   -- max length of result
 *  hostflag -- 0 = don't include hostname, 1 = include hostname
 * returns final length or 0 if not enough space
 */

/* xxx has this ever been tested??? */

int sasl_mkchal(sasl_conn_t *conn,
		char *buf,
		unsigned maxlen,
		int hostflag)
{
  sasl_rand_t *pool = NULL;
  unsigned long randnum;
  time_t now;
  unsigned len;

  len = 4			/* <.>\0 */
    + (2 * 20);			/* 2 numbers, 20 => max size of 64bit
				 * ulong in base 10 */
  if (hostflag && conn->serverFQDN)
    len += strlen(conn->serverFQDN) + 1 /* for the @ */;

  if (maxlen < len)
    return 0;

  sasl_randcreate(&pool);
  sasl_rand(pool, (char *)&randnum, sizeof(randnum));
  sasl_randfree(&pool);

  time(&now);

  if (hostflag && conn->serverFQDN)
    snprintf(buf,maxlen, "<%lu.%lu@%s>", randnum, now, conn->serverFQDN);
  else
    snprintf(buf,maxlen, "<%lu.%lu>", randnum, now);

  return strlen(buf);
}

  /* borrowed from larry. probably works :)
   * probably is also in acap server somewhere
   */
int sasl_utf8verify(const char *str, unsigned len)
{
  unsigned i;
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

#if 0
/* This was used by the audio random stuff */
static int
parityof(unsigned char ch)
{
  int ret=0;
  int lup;
  for (lup=0;lup<8;lup++)
    ret+= (ch >> lup) & 1;

  return ret;
}
#endif

/* 
 * To see why this is really bad see RFC 1750
 *
 * unfortunatly there currently is no way to make 
 * cryptographically secure pseudo random numbers
 * without specialized hardware etc...
 *
 * A note:
 *  After some relativly small number of iterations
 *  (30-50?) this may become really insecure
 *  It would be a good idea to churn() every so often
 *   Currently this is _not_ a problem
 */

static unsigned short* getranddata()
{
  unsigned short *ret;
  long curtime;
  FILE *f;

  ret=sasl_ALLOC(6);
  if (ret ==NULL) return NULL;
  memset(ret,0,6);

  /* this will probably only work on linux */
  if ((f=fopen("/dev/random","r"))!=NULL)
  {    
    fread(ret, 1, 6, f);

    fclose(f);
    return ret;
  }
  
#if 0  /* this works but is horribly slow :) */
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
#endif

  /* if all else fails just use timer 
   * this is really bad (see 1750). any other ideas tho?
   */
  curtime=(long) time(NULL);

  ret[0]=(unsigned short) (curtime >> 16);
  ret[1]=(unsigned short) (curtime & 0x0000FFFF);
  ret[2]=(unsigned short) ((curtime*7) >> 5);

  return ret;
}

int sasl_randcreate(sasl_rand_t **rpool)
{
  (*rpool)=sasl_ALLOC(sizeof(sasl_rand_t));
  if ((*rpool) ==NULL) return SASL_NOMEM;

  /* init is lazy */
  (*rpool)->initialized=-1;


  return SASL_OK;
}

void sasl_randfree(sasl_rand_t **rpool)
{
  sasl_FREE((*rpool));
}

void sasl_randseed (sasl_rand_t *rpool, const char *seed, unsigned len)
{
  /* is it acceptable to just use the 1st 3 char's given??? */
  unsigned int lup;
  
  for (lup=0;lup<3;lup++)
    if (len>lup)
      rpool->pool[lup]=seed[lup];
}

void sasl_rand (sasl_rand_t *rpool, char *buf, unsigned len)
{
  unsigned short *data;
  unsigned int lup;
  if (buf==NULL) return;

  /* see if we need to init now */
  if (rpool->initialized==-1)
  {
    data=getranddata();
    if (data==NULL)
      return; /* xxx */

    memcpy(rpool->pool, data, 6);
    
    memset(data, 0, 6); /* wipe it out */
    sasl_FREE((data));

    rpool->initialized=1;
  }

#ifdef WIN32
  for (lup=0;lup<len;lup++)
    buf[lup]= (char) (rand());
#else /* WIN32 */
  for (lup=0;lup<len;lup++)
    buf[lup]= (char) jrand48(rpool->pool);
#endif /* WIN32 */

}

void sasl_churn (sasl_rand_t *rpool, const char *data, unsigned len)
{
  unsigned int lup,spot;
  spot=0;

  for (lup=0;lup<len;lup++)
  {
    rpool->pool[spot]^=data[lup];
    spot++;
    if (spot==3)
      spot=0;
  }

}

#ifdef WIN32
/***************************************************************************** 
 * 
 *  MODULE NAME : GETOPT.C 
 * 
 *  COPYRIGHTS: 
 *             This module contains code made available by IBM 
 *             Corporation on an AS IS basis.  Any one receiving the 
 *             module is considered to be licensed under IBM copyrights 
 *             to use the IBM-provided source code in any way he or she 
 *             deems fit, including copying it, compiling it, modifying 
 *             it, and redistributing it, with or without 
 *             modifications.  No license under any IBM patents or 
 *             patent applications is to be implied from this copyright 
 *             license. 
 * 
 *             A user of the module should understand that IBM cannot 
 *             provide technical support for the module and will not be 
 *             responsible for any consequences of use of the program. 
 * 
 *             Any notices, including this one, are not to be removed 
 *             from the module without the prior written consent of 
 *             IBM. 
 * 
 *  AUTHOR:   Original author: 
 *                 G. R. Blair (BOBBLAIR at AUSVM1) 
 *                 Internet: bobblair@bobblair.austin.ibm.com 
 * 
 *            Extensively revised by: 
 *                 John Q. Walker II, Ph.D. (JOHHQ at RALVM6) 
 *                 Internet: johnq@ralvm6.vnet.ibm.com 
 * 
 *****************************************************************************/ 
 
/****************************************************************************** 
 * getopt() 
 * 
 * The getopt() function is a command line parser.  It returns the next 
 * option character in argv that matches an option character in opstring. 
 * 
 * The argv argument points to an array of argc+1 elements containing argc 
 * pointers to character strings followed by a null pointer. 
 * 
 * The opstring argument points to a string of option characters; if an 
 * option character is followed by a colon, the option is expected to have 
 * an argument that may or may not be separated from it by white space. 
 * The external variable optarg is set to point to the start of the option 
 * argument on return from getopt(). 
 * 
 * The getopt() function places in optind the argv index of the next argument 
 * to be processed.  The system initializes the external variable optind to 
 * 1 before the first call to getopt(). 
 * 
 * When all options have been processed (that is, up to the first nonoption 
 * argument), getopt() returns EOF.  The special option "--" may be used to 
 * delimit the end of the options; EOF will be returned, and "--" will be 
 * skipped. 
 * 
 * The getopt() function returns a question mark (?) when it encounters an 
 * option character not included in opstring.  This error message can be 
 * disabled by setting opterr to zero.  Otherwise, it returns the option 
 * character that was detected. 
 * 
 * If the special option "--" is detected, or all options have been 
 * processed, EOF is returned. 
 * 
 * Options are marked by either a minus sign (-) or a slash (/). 
 * 
 * No errors are defined. 
 *****************************************************************************/ 
 
#include <string.h>                 /* for strchr() */ 
 
/* static (global) variables that are specified as exported by getopt() */ 
__declspec(dllexport) char *optarg = NULL;    /* pointer to the start of the option argument  */ 
__declspec(dllexport) int   optind = 1;       /* number of the next argv[] to be evaluated    */ 
__declspec(dllexport) int   opterr = 1;       /* non-zero if a question mark should be returned */

 
/* handle possible future character set concerns by putting this in a macro */ 
#define _next_char(string)  (char)(*(string+1)) 
 
int getopt(int argc, char *argv[], char *opstring) 
{ 
    static char *pIndexPosition = NULL; /* place inside current argv string */ 
    char *pArgString = NULL;        /* where to start from next */ 
    char *pOptString;               /* the string in our program */ 
 
 
    if (pIndexPosition != NULL) { 
        /* we last left off inside an argv string */ 
        if (*(++pIndexPosition)) { 
            /* there is more to come in the most recent argv */ 
            pArgString = pIndexPosition; 
        } 
    } 
 
    if (pArgString == NULL) { 
        /* we didn't leave off in the middle of an argv string */ 
        if (optind >= argc) { 
            /* more command-line arguments than the argument count */ 
            pIndexPosition = NULL;  /* not in the middle of anything */ 
            return EOF;             /* used up all command-line arguments */ 
        } 
 
        /*--------------------------------------------------------------------- 
         * If the next argv[] is not an option, there can be no more options. 
         *-------------------------------------------------------------------*/ 
        pArgString = argv[optind++]; /* set this to the next argument ptr */ 
 
        if (('/' != *pArgString) && /* doesn't start with a slash or a dash? */ 
            ('-' != *pArgString)) { 
            --optind;               /* point to current arg once we're done */ 
            optarg = NULL;          /* no argument follows the option */ 
            pIndexPosition = NULL;  /* not in the middle of anything */ 
            return EOF;             /* used up all the command-line flags */ 
        } 
 
        /* check for special end-of-flags markers */ 
        if ((strcmp(pArgString, "-") == 0) || 
            (strcmp(pArgString, "--") == 0)) { 
            optarg = NULL;          /* no argument follows the option */ 
            pIndexPosition = NULL;  /* not in the middle of anything */ 
            return EOF;             /* encountered the special flag */ 
        } 
 
        pArgString++;               /* look past the / or - */ 
    } 
 
    if (':' == *pArgString) {       /* is it a colon? */ 
        /*--------------------------------------------------------------------- 
         * Rare case: if opterr is non-zero, return a question mark; 
         * otherwise, just return the colon we're on. 
         *-------------------------------------------------------------------*/ 
        return (opterr ? (int)'?' : (int)':'); 
    } 
    else if ((pOptString = strchr(opstring, *pArgString)) == 0) { 
        /*--------------------------------------------------------------------- 
         * The letter on the command-line wasn't any good. 
         *-------------------------------------------------------------------*/ 
        optarg = NULL;              /* no argument follows the option */ 
        pIndexPosition = NULL;      /* not in the middle of anything */ 
        return (opterr ? (int)'?' : (int)*pArgString); 
    } 
    else { 
        /*--------------------------------------------------------------------- 
         * The letter on the command-line matches one we expect to see 
         *-------------------------------------------------------------------*/ 
        if (':' == _next_char(pOptString)) { /* is the next letter a colon? */ 
            /* It is a colon.  Look for an argument string. */ 
            if ('\0' != _next_char(pArgString)) {  /* argument in this argv? */ 
                optarg = &pArgString[1];   /* Yes, it is */ 
            } 
            else { 
                /*------------------------------------------------------------- 
                 * The argument string must be in the next argv. 
                 * But, what if there is none (bad input from the user)? 
                 * In that case, return the letter, and optarg as NULL. 
                 *-----------------------------------------------------------*/ 
                if (optind < argc) 
                    optarg = argv[optind++]; 
                else { 
                    optarg = NULL; 
                    return (opterr ? (int)'?' : (int)*pArgString); 
                } 
            } 
            pIndexPosition = NULL;  /* not in the middle of anything */ 
        } 
        else { 
            /* it's not a colon, so just return the letter */ 
            optarg = NULL;          /* no argument follows the option */ 
            pIndexPosition = pArgString;    /* point to the letter we're on */ 
        } 
        return (int)*pArgString;    /* return the letter that matched */ 
    } 
} 

#ifndef PASSWORD_MAX
#  define PASSWORD_MAX 255
#endif

#include <conio.h>
char *
getpass(prompt)
const char *prompt;
{
	register char *p;
	register c;
	static char pbuf[PASSWORD_MAX];

	fprintf(stderr, "%s", prompt); (void) fflush(stderr);
	for (p=pbuf; (c = _getch())!=13 && c!=EOF;) {
		if (p < &pbuf[sizeof(pbuf)-1])
			*p++ = c;
	}
	*p = '\0';
	fprintf(stderr, "\n"); (void) fflush(stderr);
	return(pbuf);
}



#endif /* WIN32 */
