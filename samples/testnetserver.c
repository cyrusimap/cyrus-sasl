#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#include <errno.h>

#include <sasl.h>

#define DEFAULTPORT 2048

FILE *fp;
int s;
int ns;
char hostname[128]; /* xxx max */
sasl_conn_t *conn=NULL;
int uselayer=0;

extern int errno;

extern int _sasl_debug;


static void quit(void)
{
  close(s);
  exit(1);
}

/* check sasl code
 * exit if there is an error 
 */
static void saslcheck(char *msg, int result)
{
  if (result<SASL_OK)
  {
    printf("sasl error %i in %s\n",result,msg);
    exit(1);
  }
}


static void s_send(char *str, int strlength)
{
  char *tosend=str;
  unsigned int sendlen=strlength;
  int lup;

  if (uselayer==1)
  {
    int result=sasl_encode(conn,str,strlength,&tosend,&sendlen);
    saslcheck("sasl_encode",result);
  }

  printf("sending ((%s)) {%i}\n",str,sendlen);
  for (lup=0;lup<sendlen;lup++)
    printf("%i - %i\n",lup,tosend[lup]);


  if ( send(ns, tosend, sendlen,0) == -1)
  {
    /*    printf("error=[%s]\n",sys_errlist[errno]);*/
    printf("error sending: %s %i\n",str,errno);
    exit(1);
  }
  
}

static int isspace(char ch)
{
  if ((ch==' ') || (ch=='\n') || (ch=='\r') || (ch==0))
    return 1;

  return 0;
}

char buffer[1024];
int bufferlen=0;

static int readsome(void)
{
  char *ret=(char *) malloc(1000);
  unsigned int retlen;

  char tmpstr[1024];
  int tmplen;
  int result;
  /*size_t fread( void *ptr, size_t size, size_t nmemb, FILE *stream);*/
    
  tmplen=read(fileno(fp),tmpstr,200);
  printf("read %i bytes\n",tmplen);

  result=sasl_decode(conn,
		     tmpstr,tmplen,
		     &ret,&retlen);
  saslcheck("sasl_decode",result);

  if (ret!=NULL)
    printf("decode [%s]\n",ret);
  else
    printf("ret=null\n");

  memcpy(buffer+bufferlen,ret,retlen);
  bufferlen+=retlen;  
  
  printf("buffer=[%s]\n",buffer);
}

static int getachar(void)
{
  if (uselayer==0)
  {
    return fgetc(fp);

  } else {
    int ret;

    if (bufferlen<1)
      readsome();

    if (bufferlen<1)
      return -1;

    ret=buffer[0];
    bufferlen--;
    memmove(buffer,buffer+1,bufferlen);

    printf("getchar %c\n",ret);

    return ret;
  }

}

char *getimaptoken(void)
{
  char *ret=(char *) malloc(1000);
  int retlen;

  int pos=0;
  char ch;

  printf("waiting for chars\n");
    while ((ch=getachar()) != EOF)
    {
      printf("got a char %i\n",ch);
      if (isspace(ch)!=1)
	break;
    }
  
    do 
    {
      if (isspace(ch)==1)
	break;

      ret[pos]=ch;
      pos++;

      /*    printf("%c",ch);*/
      
    } while ((ch=getachar()) != EOF);
  

  if (ch==EOF)
  {
    printf("connection cut\n");
    exit(1);
  }

  ret[pos]=0;

  return ret;
}


static void saslprops(sasl_conn_t *conn)
{
  struct sockaddr_in *saddr_l=(struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  struct sockaddr_in *saddr_r=(struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  int addrsize=sizeof(struct sockaddr_in);
  int result;
  
  if (getpeername(ns,(struct sockaddr *)saddr_r,&addrsize)!=0)
    exit(1);
	
  result=sasl_setprop(conn,   SASL_IP_REMOTE, saddr_r);  
  saslcheck("sasl_setprop",result);

  addrsize=sizeof(struct sockaddr_in);
  if (getsockname(ns,(struct sockaddr *)saddr_l,&addrsize)!=0)
    exit(1);

  result=sasl_setprop(conn,   SASL_IP_LOCAL, saddr_l);	
  saslcheck("sasl_setprop",result);

}

#define AUTHCOMPLETE "A001 OK authed\r\n"

static int imapsasl(char *mech, char *service, 
		    char *prefix /* prefix for transmission ( "+ " for imap ) */
		     )
{

  int result;

  char *out,*errstr;
  unsigned int outlen;
  char *mechlist;

  /* make a connection */
  result=sasl_server_new(service,
			 hostname, /* local domain */
			 NULL, /* user domain */
			 NULL,
			 0,
			 &conn);

  saslcheck("sasl_server_new",result);
  printf("sasl_server_new\n");

  /* set properties */
  saslprops(conn);

  result=sasl_listmech(conn,
		       "tmartin",
		       ""," ","",
		       &mechlist,
		       NULL,NULL);
  saslcheck("sasl_listmech",result);
  
  printf("mechlist=[%s]\n",mechlist);
  printf("mech=[%s]\n",mech);

  result=sasl_server_start(conn,
			   mech,
			   NULL, /* in    */
			   0,    /* inlen */
			   &out,
			   &outlen,
			   (const char **) &errstr);

  saslcheck("sasl_server_start",result);

  printf("sasl_server_start\n");

  while(result!=SASL_OK)
  {     
    char *token;
    char strout[1024],decodeout[1024];
    int stroutlen,decodeoutlen;

    memset(strout,0,1000);

    /* convert to base64 */
    result=sasl_encode64(out,outlen,&strout, 1000, &stroutlen);
    saslcheck("sasl_encode64",result);
			 
    /* send data */
    s_send(prefix,strlen(prefix));
    s_send(strout,strlen(strout));
    s_send("\r\n",2);


    /* get from client */
    token=getimaptoken();
    printf("token=[%s]\n",token);

    /* decode from 64 */
    result=sasl_decode64(token,strlen(token), &decodeout,&decodeoutlen);
    saslcheck("sasl_decode64",result);


    result=sasl_server_step(conn, decodeout,decodeoutlen,
			    &out, &outlen,(const char **) &errstr);
    printf("here!!!!!\n");
    saslcheck("sasl_server_step",result);

  }
  
  printf("authentication complete\n");

  return 1;
}

#define SMTP_INITMSG "220 cmu test smtp server\r\n"
#define SMTP_SUCESS "235 OK Authenticated\r\n"

#define SMTP_NONE 20
#define SMTP_AUTH 21

static void smtpmode(void)
{
  char *authtype;

  int state=SMTP_NONE;

  /* send server init message first */
  s_send(SMTP_INITMSG,strlen(SMTP_INITMSG));
  
  while(1)
  {
    char *line=getimaptoken();
    printf("line=[%s]\n",line);

    switch(state)
    {

    case SMTP_NONE:
      if (strcasecmp(line,"AUTH")==0)
	state=SMTP_AUTH;
      else if (strcasecmp(line,"QUIT")==0) {	
	quit();
      } else {
	char buf[1024];
	sprintf(buf,"command [%s] not understood\r\n",line);
	s_send(buf,strlen(buf));
      }
      break;
    
    case SMTP_AUTH:
      authtype=line;
      printf("authtype=%s\n",authtype);

      if (imapsasl(authtype,"smtp","334 ")==1)
      {
	s_send(SMTP_SUCESS,strlen(SMTP_SUCESS));
	uselayer=1;
      }

      state=SMTP_NONE;
      break;


    }
  }
}

#define NONE    10
#define GOTTAG  11
#define GOTAUTH 12

#define IMAP_INITMSG "* OK IMAP test server\r\n"

static void imapmode(void)
{
  char *authtype;

  int state=NONE;

  /* send server init message first */
  s_send(IMAP_INITMSG,strlen(IMAP_INITMSG));
  

  while(1)
  {
    char *line=getimaptoken();
    printf("line=[%s]\n",line);

    switch(state)
    {

    case NONE:
      state=GOTTAG;
      break;
    
    case GOTTAG:
      if (strncmp(line,"AUTHENTICATE",strlen("AUTHENTICATE"))==0)
	state=GOTAUTH;
      if (strncmp(line,"CAPABILITY",strlen("CAPABILITY"))==0)
	s_send("ok",2);
      break;

    case GOTAUTH:
      authtype=line;
      s_send("gotauth\r\n",9);
      printf("authtype=%s\n",authtype);

      imapsasl(authtype,"imap","+ ");

      uselayer=1;

      state=NONE;
      break;


    }
  }

}


static acceptconnection(int port)
{
  struct hostent *hp;
  int i;
  struct sockaddr_in sin;
  struct sockaddr_in fsin;
  int fromlen=sizeof(struct sockaddr_in);


  /* get our hostname */
  gethostname(hostname, sizeof(hostname));


  /* get ip address */
  if ((hp=gethostbyname(hostname)) == NULL)
  {
    printf("host unknown %s\n",hostname);
    exit(1);
  }


  if ((s=socket(AF_INET, SOCK_STREAM, 0)) <0)
  {
    printf("error with the socket");
    exit(1);
  }

  sin.sin_family=AF_INET;
  sin.sin_port= htons(port);
  bcopy(hp->h_addr, &sin.sin_addr, hp->h_length);

  /* bind it */
  if (bind(s,(const struct sockaddr *) &sin, sizeof(sin)) < 0 )
  {
    printf("bind error");
    exit(1);
  }

  printf("listening on port %i...\n",port);
  
  /* listen on socket */
  if (listen(s, 5) < 0)
  {
    printf("listen error: errno=%i\n",errno);
    exit(1);
  }

  /* accept connection */
  if ((ns=accept(s,(struct sockaddr *) &fsin, &fromlen)) <0)
  {
    printf("accept error: errno=%i\n",errno);
    exit(1);
  }

  fp=fdopen(ns,"r");


}

static void usage(void)
{
  printf("usage: testnetserver -p port -m mode\n");
  printf("mode:= smtp | imap\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int result;
  int port=DEFAULTPORT;
  int lup;
  char *mode;
  char c;
  extern char *optarg;
  
  _sasl_debug=-1;

  /* initialize sasl */
  result=sasl_server_init(NULL,"CMU_testserver");
  if (result!=SASL_OK)
  {
    printf("sasl_server_init error: %i\n",result);
    exit(1);
  }


  while ((c = getopt(argc, argv, "p:m:")) != EOF)
    switch (c) {
    case 'p': /* port */
      port=atoi(optarg);
      printf("port=%i\n",port);
      break;
    case 'm':
      mode = optarg;
      printf("mode = %s\n", mode);
      break;
    case '?':
      printf("Unrecognized arguement\n");
      usage();
    }

  acceptconnection(port);

  if (strcasecmp(mode,"smtp")==0)
    smtpmode(); 
  else if (strcasecmp(mode,"imap")==0)
    imapmode();
  else
    printf("undefined mode: \n",mode);

}
