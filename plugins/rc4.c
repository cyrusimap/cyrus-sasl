/* rc4.c -- rc4 functions
 * Tim Martin
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

/******************************
 *
 * RC4 functions
 *
 *****************************/

static int init_rc4(context_t *text, char *key, int keylen)
{
  int lup;
  int i, j;
  unsigned char *K;

  VL(("Initializing rc-4 with keylen=%i\n",keylen));

  /* initialize sbox */
  text->sbox=(char *) text->malloc(256);  
  K=(char *) text->malloc(256);  

  /* allocate for it */


  /* fill in linearly s0=0 s1=1... */
  for (lup=0;lup<256;lup++)
    text->sbox[lup]=lup;

  for (lup=0;lup<256;lup++)
    K[lup]=key[ lup%keylen];

  j=0;
  for (i=0;i<256;i++)
  {
    char tmp;
    /* j = (j + Si + Ki) mod 256 */
    j=(j+text->sbox[i]+K[i])%256;

    /* swap Si and Sj */
    tmp=text->sbox[i];
    text->sbox[i]=text->sbox[j];
    text->sbox[j]=tmp;
  }

  /* zero and free K */
  memset(K,0,256);
  text->free(K);

  /* counters initialized to 0 */
  text->i=0;
  text->j=0;

  VL(("Initialized rc4\n"));

  return SASL_OK;
}

static int enc_rc4(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   char **output,
		   unsigned *outputlen)
{
  int tmp;
  int i=text->i;
  int j=text->j;
  int t;
  int K;
  unsigned int lup;

  *outputlen=inputlen;

  for (lup=0;lup<inputlen;lup++)
  {
    i=(i+1) %256;

    j=(j + text->sbox[i] ) %256;

    /* swap Si and Sj */
    tmp=text->sbox[i];
    text->sbox[i]=text->sbox[j];
    text->sbox[j]=tmp;
  
    t=( text->sbox[i] + text->sbox[j]) %256;
    
    K=text->sbox[t];

    /* byte K is Xor'ed with plaintext */
    (*output)[lup]=input[lup] ^ K;

  }

  text->i=i;
  text->j=j;
  return SASL_OK;
}

static int dec_rc4(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   char **output,
		   unsigned *outputlen)
{
  int tmp;
  int i=text->i;
  int j=text->j;
  int t;
  int K;
  unsigned int lup;

  *output = (char *) text->malloc(inputlen);
  if (*output==NULL) return SASL_NOMEM;
  *outputlen=inputlen;

  for (lup=0;lup<inputlen;lup++)
  {
    i=(i+1) %256;

    j=(j + text->sbox[i] ) %256;

    /* swap Si and Sj */
    tmp=text->sbox[i];
    text->sbox[i]=text->sbox[j];
    text->sbox[j]=tmp;
  
    t=( text->sbox[i] + text->sbox[j]) %256;
    
    K=text->sbox[t];

    /* byte K is Xor'ed with plaintext */
    (*output)[lup]=input[lup] ^ K;

  }

  text->i=i;
  text->j=j;
  return SASL_OK;
}
