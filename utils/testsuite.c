/* testsuite.c -- Stress the library a little
 * Tim Martin
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

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

/*
 * TODO:
 *  put in alloc() routines that fail occasionally.
 *  verify ssf's
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <sasl.h>
#include <saslutil.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

char myhostname[1024+1];
#define MAX_STEPS 7 /* maximum steps any mechanism takes */

#define CLIENT_TO_SERVER "Hello. Here is some stuff"

char *username = "tmartin";
char *authname = "tmartin";
char *password = "1234";

/* our types of failures */
typedef enum {
    NOTHING = 0,
    ONEBYTE_RANDOM, /* replace one byte with something random */
    ONEBYTE_NULL,   /* replace one byte with a null */
    ONEBYTE_QUOTES, /* replace one byte with a double quote (try to fuck with digest-md5) */   
    ONLY_ONE_BYTE,  /* send only one byte */
    ADDSOME,        /* add some random bytes onto the end */
    SHORTEN,        /* shorten the string some */
    REASONABLE_RANDOM, /* send same size but random */
    REALLYBIG,       /* send something absurdly large (all random)*/
    NEGATIVE_LENGTH, /* send negative length */
    CORRUPT_SIZE /* keep this one last */
} corrupt_type_t;

typedef void *foreach_t(char *mech, void *rock);

typedef struct tosend_s {

    corrupt_type_t type; /* type of corruption to make */
    int step; /* step it should send bogus data on */

} tosend_t;

int good_getopt(void *context __attribute__((unused)), 
		const char *plugin_name __attribute__((unused)), 
		const char *option,
		const char **result,
		unsigned *len)
{
    if (strcmp(option,"pwcheck_method")==0)
    {
	*result = "sasldb";
	if (len)
	    *len = strlen("sasldb");
	return SASL_OK;
    }

    return SASL_FAIL;
}

static struct sasl_callback goodsasl_cb[] = {
    { SASL_CB_GETOPT, &good_getopt, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int givebadpath(void * context __attribute__((unused)), 
		char ** path)
{
    int lup;
    *path = malloc(10000);    
    strcpy(*path,"/tmp/is/not/valid/path/");

    for (lup = 0;lup<1000;lup++)
	strcat(*path,"a/");

    return SASL_OK;
}

static struct sasl_callback withbadpathsasl_cb[] = {
    { SASL_CB_GETPATH, &givebadpath, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int giveokpath(void * context __attribute__((unused)), 
		char ** path)
{
    *path = malloc(1000);
    strcpy(*path,"/tmp/");

    return SASL_OK;
}

static struct sasl_callback withokpathsasl_cb[] = {
    { SASL_CB_GETPATH, &giveokpath, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static struct sasl_callback emptysasl_cb[] = {
    { SASL_CB_LIST_END, NULL, NULL }
};

void fatal(char *str)
{
    printf("Failed with: %s\n",str);
    exit(3);
}

char really_long_string[32000];

/*
 * Setup some things for test
 */
void init(void)
{
    int lup;
    int result;

    srand(time(NULL));

    for (lup=0;lup<32000;lup++)
	really_long_string[lup] = '0' + (rand() % 10);

    really_long_string[30000+ rand() % 2000] = '\0';

    result = gethostname(myhostname, sizeof(myhostname)-1);
    if (result == -1) fatal("gethostname");
}

/*
 * Tests for sasl_server_init
 */

void test_init(void)
{
    int result;

    /* sasl_done() before anything */
    sasl_done();

    /* Try passing appname a really long string (just see if it crashes it)*/

    result = sasl_server_init(NULL,really_long_string);
    sasl_done();

    /* try passing NULL name */
    result = sasl_server_init(emptysasl_cb, NULL);

    if (result == SASL_OK) fatal("Allowed null name to sasl_server_init");

    /* this calls sasl_done when it wasn't inited */
    sasl_done();

    /* try giving it a different path for where the plugins are */
    result = sasl_server_init(withokpathsasl_cb, "Tester");

    if (result!=SASL_OK) fatal("Didn't deal with ok callback path very well");
    sasl_done();

    /* try giving it an invalid path for where the plugins are */
    result = sasl_server_init(withbadpathsasl_cb, NULL);

    if (result==SASL_OK) fatal("Allowed invalid path");
    sasl_done();
}


/* 
 * Tests sasl_listmech command
 */

void test_listmech(void)
{
    sasl_conn_t *saslconn;
    int result;
    char *str = NULL;
    int plen;
    int lup;
    int pcount;

    /* test without initializing library */
    result = sasl_listmech(NULL, /* conn */
			   NULL,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    /*    printf("List mech without library initialized: %s\n",sasl_errstring(result,NULL,NULL));*/
    if (result == SASL_OK) fatal("Failed sasl_listmech() with NULL saslconn");




    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK) {
	fatal("");
    }


    /* Test with really long user */

    result = sasl_listmech(saslconn,
			   really_long_string,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long user");

    if (str[0]!='[') fatal("Failed sasl_listmech() with long user (didn't start with '['");
    free(str);

    /* Test with really long prefix */

    result = sasl_listmech(saslconn,
			   NULL,
			   really_long_string,
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("failed sasl_listmech() with long prefix");

    if (str[0]!=really_long_string[0]) fatal("failed sasl_listmech() with long prefix (str is suspect)");
    free(str);

    /* Test with really long suffix */

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   "-",
			   really_long_string,
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long suffix");
    free(str);

    /* Test with really long seperator */

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   really_long_string,
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long seperator");
    free(str);

    /* Test contents of output string is accurate */
    result = sasl_listmech(saslconn,
			   NULL,
			   "",
			   "%",
			   "",
			   &str,
			   &plen,
			   &pcount);

    if (result != SASL_OK) fatal("Failed sasl_listmech()");

    if ((int) strlen(str)!=plen) fatal("Length of string doesn't match what we were told");
    
    for (lup=0;lup<plen;lup++)
	if (str[lup]=='%')
	    pcount--;

    pcount--;
    if (pcount != 0)
    {
	printf("mechanism string = %s\n",str);
	printf("Mechs left = %d\n",pcount);
	fatal("Number of mechs received doesn't match what we were told");
    }

    free(str);
    /* Call sasl done then make sure listmech doesn't work anymore */
    sasl_dispose(&saslconn);
    sasl_done();

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result == SASL_OK) fatal("Called sasl_done but listmech still works\n");

}

/*
 * Perform tests on the random utilities
 */

void test_random(void)
{
    sasl_rand_t *rpool;
    int lup;
    char buf[4096];

    /* make sure it works consistantly */

    for (lup = 0;lup<10;lup++)
    {
	if (sasl_randcreate(&rpool) != SASL_OK) fatal("sasl_randcreate failed");
	sasl_randfree(&rpool);
    }

    /* try seeding w/o calling rand_create first */
    rpool = NULL;
    sasl_randseed(rpool, "seed", 4);
    

    /* try seeding with bad values */
    sasl_randcreate(&rpool);
    sasl_randseed(rpool, "seed", 0);
    sasl_randseed(rpool, NULL, 0);
    sasl_randseed(rpool, NULL, 4);    
    sasl_randfree(&rpool);

    /* try churning with bad values */
    sasl_randcreate(&rpool);
    sasl_churn(rpool, "seed", 0);
    sasl_churn(rpool, NULL, 0);
    sasl_churn(rpool, NULL, 4);    
    sasl_randfree(&rpool);

    /* try seeding with a lot of crap */
    sasl_randcreate(&rpool);
    
    for (lup=0;lup<(int) sizeof(buf);lup++)
    {
	buf[lup] = (rand() % 256);	
    }
    sasl_randseed(rpool, buf, sizeof(buf));
    sasl_churn(rpool, buf, sizeof(buf));

    sasl_randfree(&rpool);
}

/*
 * Test SASL base64 conversion routines
 */

void test_64(void)
{
    char orig[4096];
    char enc[8192];
    int encsize;
    int lup;

    /* make random crap and see if enc->dec produces same as original */
    for (lup=0;lup<(int) sizeof(orig);lup++)
	orig[lup] = (char) (rand() % 256);
    
    if (sasl_encode64(orig, sizeof(orig), enc, sizeof(enc), &encsize)!=SASL_OK) 
	fatal("encode64 failed when we didn't expect it to");
    
    if (sasl_decode64(enc, encsize, enc, &encsize)!=SASL_OK)
	fatal("decode failed when didn't expect");
    
    if (encsize != sizeof(orig)) fatal("Now has different size");
    
    for (lup=0;lup<(int) sizeof(orig);lup++)
	if (enc[lup] != orig[lup])
	    fatal("enc64->dec64 doesn't match");

    /* try to get a SASL_BUFOVER */
    
    if (sasl_encode64(orig, sizeof(orig)-1, enc, 10, &encsize)!=SASL_BUFOVER)
	fatal("Expected SASL_BUFOVER");


    /* pass some bad params */
    if (sasl_encode64(NULL, 10, enc, sizeof(enc), &encsize)==SASL_OK)
	fatal("Said ok to null data");

    if (sasl_encode64(orig, sizeof(orig), enc, sizeof(enc), NULL)!=SASL_OK)
	fatal("Didn't allow null return size");
    
}


/* callbacks we support */
static sasl_callback_t client_callbacks[] = {
  {
#ifdef SASL_CB_GETREALM
    SASL_CB_GETREALM, NULL, NULL
  }, {
#endif
    SASL_CB_USER, NULL, NULL
  }, {
    SASL_CB_AUTHNAME, NULL, NULL
  }, {
    SASL_CB_PASS, NULL, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

void interaction (int id, const char *prompt,
		  char **tresult, unsigned int *tlen)
{
    char result[1024];
    
    if (id==SASL_CB_PASS) {
	*tresult=(char *) strdup(password);
	*tlen=strlen(*tresult);
	return;
    } else if (id==SASL_CB_USER) {
	if (username != NULL) {
	    strcpy(result, username);
	} else {
	    fatal("no username");
	}
    } else if (id==SASL_CB_AUTHNAME) {
	if (authname != NULL) {
	    strcpy(result, authname);
	} else {
	    fatal("no authname");
	}
#ifdef SASL_CB_GETREALM
    } else if ((id==SASL_CB_GETREALM)) {
      strcpy(result, myhostname);
#endif
    } else {
	int c;
	
	printf("%s: ",prompt);
	fgets(result, sizeof(result) - 1, stdin);
	c = strlen(result);
	result[c - 1] = '\0';
    }

    *tlen = strlen(result);
    *tresult = (char *) malloc(*tlen+1);

    memset(*tresult, 0, *tlen+1);
    memcpy((char *) *tresult, result, *tlen);
}

void fillin_correctly(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist->id, tlist->prompt,
		(void *) &(tlist->result), 
		&(tlist->len));
    tlist++;
  }

}

void set_properties(sasl_conn_t *conn, char *serverFQDN, int port)
{
  struct sockaddr_in addr;
  struct hostent *hp;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
    perror("gethostbyname");
    fatal("");
  }

  addr.sin_family = 0;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (sasl_setprop(conn, SASL_IP_REMOTE, &addr)!=SASL_OK)
      fatal("set_prop() failed");
  
  if (sasl_setprop(conn, SASL_IP_LOCAL, &addr)!=SASL_OK)
      fatal("set_prop() failed");

}

/*
 * This corrupts the string for us
 */

void corrupt(corrupt_type_t type, char *in, int inlen, char **out, int *outlen)
{
    int lup;

    switch (type)
	{
	case NOTHING:
	    *out = in;
	    *outlen = inlen;
	    break;
	case ONEBYTE_RANDOM: /* corrupt one byte */

	    if (inlen>0)
		in[ (rand() % inlen) ] = (char) (rand() % 256);

	    *out = in;
	    *outlen = inlen;

	    break;
	case ONEBYTE_NULL:
	    if (inlen>0)
		in[ (rand() % inlen) ] = '\0';

	    *out = in;
	    *outlen = inlen;
	    break;
	case ONEBYTE_QUOTES:
	    if (inlen>0)
		in[ (rand() % inlen) ] = '"';

	    *out = in;
	    *outlen = inlen;
	    break;
	case ONLY_ONE_BYTE:
	    free(in);
	    *out = (char *) malloc(1);
	    (*out)[0] = (char) (rand() % 256);
	    *outlen = 1;
	    break;

	case ADDSOME:
	    *outlen = inlen+ (rand() % 100);
	    *out = (char *) malloc(*outlen);
	    memcpy( *out, in, inlen);
	    
	    for (lup=inlen;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() %256);

	    free(in);
	    break;

	case SHORTEN:
	    if (inlen > 0)
	    {
		*outlen = (rand() % inlen);
		*out = (char *) malloc(*outlen);
		memcpy(*out, in, *outlen);
		free(in);
	    } else {
		*outlen = inlen;
		*out = in;
	    }
	    break;
	case REASONABLE_RANDOM:
	    *outlen = inlen;
	    *out = (char *) malloc(*outlen);
	    for (lup=0;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() % 256);
	    free(in);
	    break;
	case REALLYBIG:
	    *outlen = rand() % 50000;
	    *out = (char *) malloc( *outlen);
	    
	    for (lup=0;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() % 256);
	    
	    free(in);
	    break;
	case NEGATIVE_LENGTH:

	    *out = in;
	    if (inlen == 0) inlen = 10;
	    *outlen = -1 * (rand() % inlen);
	    
	    break;
	default:
	    fatal("Invalid corruption type");
	    break;
	}
}

void sendbadsecond(char *mech, void *rock)
{
    int result;
    sasl_conn_t *saslconn;
    sasl_conn_t *clientconn;
    char *out, *dec = NULL;
    unsigned outlen, declen;
    sasl_interact_t *client_interact=NULL;
    const char *mechusing;
    char *service = "rcmd";
    const char *errstr;
    int mystep = 0; /* what step in the authentication are we on */
    int mayfail = 0; /* we did some corruption earlier so it's likely to fail now */
    char *tofree;
    
    tosend_t *send = (tosend_t *)rock;

    printf("%s --> start\n",mech);
    
    if (strcmp(mech,"GSSAPI")==0) service = "imap";

    if (sasl_client_init(client_callbacks)!=SASL_OK) fatal("Unable to init client");
    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("");

    /* client new connection */
    if (sasl_client_new(service,
			myhostname,
			NULL,
			0,
			&clientconn)!= SASL_OK) fatal("sasl_client_new() failure");

    set_properties(clientconn, myhostname,0);

    if (sasl_server_new(service, myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK) {
	fatal("");
    }
    set_properties(saslconn, myhostname ,0);

    

    do {
	result = sasl_client_start(clientconn,mech,
				   NULL, &client_interact,
				   &out, &outlen,
				   &mechusing);

	if (result == SASL_INTERACT) fillin_correctly(client_interact);

    } while (result == SASL_INTERACT);
			       
    if (result < 0)
    {
	printf("%s\n",sasl_errstring(result,NULL,NULL));
	fatal("sasl_client_start() error");
    }

    if (mystep == send->step)
    {
	corrupt(send->type, out, outlen, &out, &outlen);
	mayfail = 1;
    }
    tofree = out;
    result = sasl_server_start(saslconn,
			       mech,
			       out,
			       outlen,
			       &out,
			       &outlen,
			       &errstr);

    if (mayfail)
    {
	if (result >= 0)
	    printf("WARNING: We did a corruption but it still worked\n");
	else {
	    if (tofree) free(tofree);
	    if (out!=tofree) free(out);
	    goto done;
	}
    } else {
	if (result < 0) 
	{
	    if (errstr) printf ("%s\n",errstr);
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_server_start() error");
	}
    }
    if (tofree) free(tofree);
    mystep++;

    while (result == SASL_CONTINUE) {

	if (mystep == send->step)
	{
	    corrupt(send->type, out, outlen, &out, &outlen);
	    mayfail = 1;
	}
	tofree = out;
	do {
	    result = sasl_client_step(clientconn,
				      out, outlen,
				      &client_interact,
				      &out, &outlen);
	    
	    if (result == SASL_INTERACT) fillin_correctly(client_interact);
	} while (result == SASL_INTERACT);

	if (mayfail == 1)
	{
	    if (result >= 0)
		printf("WARNING: We did a corruption but it still worked\n");
	    else {
		if (tofree) free(tofree);
		if (out!=tofree) free(out);
		goto done;
	    }
	} else {
	    if (result < 0) 
	    {
		if (errstr) printf ("%s\n",errstr);
		printf("%s\n",sasl_errstring(result,NULL,NULL));
		fatal("sasl_client_step() error");
	    }
	}
	if (tofree) free(tofree);
	mystep++;


	if (mystep == send->step)
	{
	    corrupt(send->type, out, outlen, &out, &outlen);
	    mayfail = 1;
	}
	tofree = out;
	result = sasl_server_step(saslconn,
				  out,
				  outlen,
				  &out,
				  &outlen,
				  NULL);
	
	if (mayfail == 1)
	{
	    if (result >= 0)
		printf("WARNING: We did a corruption but it still worked\n");
	    else {
		if (tofree) free(tofree);
		if (out!=tofree) free(out);
		goto done;
	    }
	} else {
	    if (result < 0) 
	    {
		if (errstr) printf ("%s\n",errstr);
		printf("%s\n",sasl_errstring(result,NULL,NULL));
		fatal("sasl_server_step() error");
	    }
	}
	if (tofree) free(tofree);
	mystep++;

    }

    if (out) free(out);
    printf("%s --> %s\n",mech,sasl_errstring(result,NULL,NULL));

    /* client to server */
    
    result = sasl_encode(clientconn, CLIENT_TO_SERVER, strlen(CLIENT_TO_SERVER), &out, &outlen);
    if (result != SASL_OK) fatal("Error encoding");

    if (mystep == send->step)
    {
	corrupt(send->type, out, outlen, &out, &outlen);
	mayfail = 1;
    } 
    tofree = out;
    dec = NULL;
    result = sasl_decode(saslconn, out, outlen, &dec, &declen);
    if (mayfail == 1)
    {
	if (result >= 0)
	    printf("WARNING: We did a corruption but it still worked\n");
	else {
	    if (out) free(out);
	    if (dec) free(dec);
	    goto done;
	}
    } else {
	if (result < 0) 
	{
	    if (errstr) printf ("%s\n",errstr);
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_decode() failure");
	}
    }
    if (out) free(out);
    if (dec) free(dec);
    mystep++;

    /* no need to do other direction since symetric */

 done:
    sasl_dispose(&clientconn);
    sasl_dispose(&saslconn);
    sasl_done();
}

/*
 * Apply the given function to each machanism 
 */

void foreach_mechanism(foreach_t *func, void *rock)
{
    char *str, *start, *tofree;
    sasl_conn_t *saslconn;
    int result;

    /* Get the list of mechanisms */
    sasl_done();
    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK) {
	fatal("");
    }

    result = sasl_listmech(saslconn,
			   NULL,
			   "",
			   "\n",
			   "",
			   &str,
			   NULL,
			   NULL);
    tofree = str;
    sasl_dispose(&saslconn);
    sasl_done();

    /* call the function for each mechanism */
    start = str;
    while (*start != '\0')
    {
	while ((*str != '\n') && (*str != '\0'))
	    str++;

	if (*str == '\n')
	{
	    *str = '\0';
	    str++;
	}

	func(start, rock);

	start = str;
    }
    free(tofree);
}

void test_serverstart(void)
{
    int result;
    sasl_conn_t *saslconn;
    char *out;
    unsigned outlen;
    tosend_t tosend;
    int lup;

    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK) {
	fatal("");
    }


    /* Test null connection */
    result = sasl_server_start(NULL,
			       "foobar",
			       NULL,
			       0,
			       NULL,
			       NULL,
			       NULL);
    
    if (result == SASL_OK) fatal("Said ok to null sasl_conn_t in sasl_server_start()");

    /* send plausible but invalid mechanism */
    result = sasl_server_start(saslconn,
			       "foobar",
			       NULL,
			       0,
			       &out,
			       &outlen,
			       NULL);

    if (result == SASL_OK) fatal("Said ok to invalid mechanism");

    /* send really long and invalid mechanism */
    result = sasl_server_start(saslconn,
			       really_long_string,
			       NULL,
			       0,
			       &out,
			       &outlen,
			       NULL);

    if (result == SASL_OK) fatal("Said ok to invalid mechanism");

    sasl_dispose(&saslconn);
    sasl_done();

    tosend.step = 500;
    printf("trying to do correctly\n");
    foreach_mechanism((foreach_t *) &sendbadsecond,&tosend);

    for (lup=0;lup<50;lup++)
    {
	tosend.type = rand() % CORRUPT_SIZE;
	tosend.step = lup % MAX_STEPS;

	printf("trying random crap (%d of %d)\n",lup,100);
	foreach_mechanism((foreach_t *) &sendbadsecond,&tosend);
    }
}

void create_ids(void)
{
    sasl_conn_t *saslconn;
    int result;

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK)
	fatal("");
    
    /* Try to set password then check it */
    
    result = sasl_setpass(saslconn, username, password, strlen(password), SASL_SET_CREATE, NULL);
    if (result != SASL_OK)
	fatal("Error setting password. Do we have write access to sasldb?");
    
    result = sasl_checkpass(saslconn, username, strlen(username),
			    password, strlen(password), NULL);
    if (result != SASL_OK)
	fatal("Unable to verify password we just set");

    /* now delete user and make sure can't find him anymore */
    result = sasl_setpass(saslconn, username, password, strlen(password), SASL_SET_DISABLE, NULL);
    if (result != SASL_OK)
	fatal("Error disabling password. Do we have write access to sasldb?");
    
    result = sasl_checkpass(saslconn, username, strlen(username),
			    password, strlen(password), NULL);
    if (result != SASL_NOUSER)
	fatal("Didn't get SASL_NOUSER");

    /* try bad params */
    if (sasl_setpass(NULL,username, password, strlen(password), SASL_SET_CREATE, NULL)==SASL_OK)
	fatal("Didn't specify saslconn");
    if (sasl_setpass(saslconn,username, password, 0, SASL_SET_CREATE, NULL)==SASL_OK)
	fatal("Allowed password of zero length");
    if (sasl_setpass(saslconn,username, password, strlen(password), 43, NULL)==SASL_OK)
	fatal("Gave wierd code");

    if (sasl_setpass(saslconn,really_long_string, password, strlen(password), 
		     SASL_SET_CREATE, NULL)!=SASL_OK)
	fatal("Didn't allow really long username");

    if (sasl_setpass(saslconn,"bob" ,really_long_string, strlen(really_long_string), 
		     SASL_SET_CREATE, NULL)!=SASL_OK)
	fatal("Didn't allow really long password");

    result = sasl_setpass(saslconn,"frank" ,password, strlen(password), 
		     SASL_SET_DISABLE, NULL);

    if ((result!=SASL_NOUSER) && (result!=SASL_OK))
	{
	    printf("error = %d\n",result);
	    fatal("Disabling non-existant didn't return SASL_NOUSER");
	}
    

    /* Now set the user again (we use for rest of program) */
    result = sasl_setpass(saslconn, username, password, strlen(password), SASL_SET_CREATE, NULL);
    if (result != SASL_OK)
	fatal("Error setting password. Do we have write access to sasldb?");

    /* cleanup */
    sasl_dispose(&saslconn);
    sasl_done();
}

/*
 * Test the checkpass routine
 */

void test_checkpass(void)
{
    sasl_conn_t *saslconn;

    /* try without initializing anything */
    sasl_checkpass(NULL, username, strlen(username),
		   password, strlen(password), NULL);

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, SASL_SECURITY_LAYER, 
			&saslconn) != SASL_OK)
	fatal("");

    /* make sure works for general case */

    if (sasl_checkpass(saslconn, username, strlen(username),
		       password, strlen(password), NULL)!=SASL_OK)
	fatal("sasl_checkpass() failed on simple case");

    /* NULL saslconn */
    if (sasl_checkpass(NULL, username, strlen(username),
		   password, strlen(password), NULL) == SASL_OK)
	fatal("Suceeded with NULL saslconn");

    /* NULL username */
    if (sasl_checkpass(saslconn, NULL, strlen(username),
		   password, strlen(password), NULL) == SASL_OK)
	fatal("Suceeded with NULL username");

    /* NULL password */
    if (sasl_checkpass(saslconn, username, strlen(username),
		   NULL, strlen(password), NULL) == SASL_OK)
	fatal("Suceeded with NULL password");

    sasl_dispose(&saslconn);
    sasl_done();
}

void notes(void)
{
    printf("NOTE:\n");
    printf("-For KERBEROS_V4 must be able to read srvtab file (usually /etc/srvtab)\n");
    printf("-For GSSAPI must be able to read srvtab (? /etc/krb5.keytab ? )\n");
    printf("-Must be able to read and write to sasldb.\n");
    printf("\n\n");
}


int main()
{
    notes();

    init();

    create_ids();
    printf("Created id's in sasldb... ok\n");

    test_checkpass();
    printf("Checking plaintext passwords... ok\n");

    test_random();
    printf("Random number functions... ok\n");

    test_64();
    printf("Tested base64 functions... ok\n");

    test_init();
    printf("Tests of sasl_server_init()... ok\n");

    test_listmech();
    printf("Tests of sasl_listmech()... ok\n");
    

    test_serverstart();
    printf("Tests of sasl_server_start()... ok\n");

    printf("All tests seemed to go ok\n");

    exit(0);
}
