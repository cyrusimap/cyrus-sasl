/* Create dbm files for use with scram-md5 mechanism
 * Tim Martin 
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

#define SCRAMDBPATH "~/pass"
#include <gdbm.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"


struct scram_entry
{
  char salt[8];
  char verifier[16];
  char serverkey[16];
};

GDBM_FILE db;

char * make_serverkey(char salt[8], char secret[64])
{
  unsigned char digest1[16], server_ver[16];
  int lup;
  char *ret;

  hmac_md5((unsigned char *) salt,8,
	   (unsigned char *) secret,64,digest1);

  /* create the server ver now */
  hmac_md5((unsigned char *) salt,8,
	   (unsigned char *) digest1,16,server_ver);

  ret=malloc(16);
  memcpy(ret, server_ver, 16);
  return ret;
}

char * make_pads(char secret[64])
{
  MD5_CTX ver_i, ver_o;
  unsigned char k_ipad[65];
  unsigned char k_opad[65];  
  int len=sizeof(MD5_CTX);
  char *ret;
  int lup;


  memcpy(k_ipad, secret, 64);
  memcpy(k_opad, secret, 64);

  for (lup=0; lup<64; lup++) 
  {
    k_ipad[lup] ^= 0x36;
    k_opad[lup] ^= 0x5c;
  }

  MD5Init(&ver_i);              
  MD5Update(&ver_i, k_ipad, 64);

  MD5Init(&ver_o);              
  MD5Update(&ver_o, k_opad, 64);

  ret=malloc(len*2);
  memcpy(ret, ver_i.state, len);
  memcpy(ret+len, ver_o.state, len);

  return ret;
}

char * make_verifier(char salt[8],char secret[64])
{
  unsigned char digest1[16], digest2[16], digest3[16];
  MD5_CTX tctx;
  int lup;
  char *ret;

  hmac_md5((unsigned char *) salt,8,
	   (unsigned char *) secret,64,digest1);

  /* erase secret from memory */
    
  /* step C */
  MD5Init(&tctx); 
  MD5Update(&tctx, digest1, 16); 
  MD5Final(digest2, &tctx); 

  /* step D */
  MD5Init(&tctx); 
  MD5Update(&tctx, digest2, 16); 
  MD5Final(digest3, &tctx); 

  ret=malloc(16);
  memcpy(ret, digest3, 16);
  return ret;
}

void addkey()
{
  char username[1024];
  char password[1024];
  char salt[1024];
  datum name;
  datum pass;
  int lup;
  char *serverkey;
  char *verifier;
  int len=sizeof(MD5_CTX);

  unsigned char entry[8+len*2];

  printf("Enter username to add: ");
  scanf("%s",&username);
  name.dptr=username;
  name.dsize=strlen(username);

  do {
    printf("Enter salt to add (8 chars): ");
    scanf("%s",&salt);
  } while (strlen(salt)!=8);

  memcpy(entry, salt, 8);
  
  memset(password, 0, 65);
  printf("Enter password to add: ");
  scanf("%s",&password);

  verifier=make_pads(password);

  memcpy(entry+8, verifier, len*2);

  pass.dptr=entry;
  pass.dsize=8+len*2;
  
  (void) gdbm_store(db, name, pass, GDBM_INSERT);


}

void deletekey()
{
  char username[1024];
  datum name;

  printf("Enter username to delete: ");
  scanf("%s",&username);
  name.dptr=username;
  name.dsize=strlen(username);

  gdbm_delete(db, name);

}

void list_records()
{
  datum key,nextkey;

  printf("Users in file:\n");
  key = gdbm_firstkey ( db );
  while ( key.dptr )
  {
    printf("[%s]\n",key.dptr);
    nextkey = gdbm_nextkey ( db, key );    
    key = nextkey;
  }
}

void show_instructions()
{
  printf("a - add user\n");
  printf("d - delete user\n");
  printf("l - list users in file\n");
  printf("q - quit\n");
  printf("h - show this help\n");
}

main()
{

  char ch;
  


  /* Open the database                      */
  db = gdbm_open("p", 512, O_RDWR, 0660,NULL);


  show_instructions();

  do {
    printf(":) ");
    ch=getchar();
    printf("\n");

    switch(ch)
    {
      case 'a':   addkey(); break;
      case 'd':   deletekey(); break;
      case 'l':   list_records(); break;
      case 'h':  show_instructions();break;
      case '\n': break;
      defualt:    printf("unknown command\n");
    }


  } while (ch!='q');



  /* Close the database */
  gdbm_close(db);
  return (0);

}

