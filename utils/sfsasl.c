#include <config.h>
#include <stdlib.h>
#include <sasl.h>
#include <sfio.h>

/* sf discipline to add sasl
 */

typedef struct _sasldisc
{
    Sfdisc_t	disc;
    sasl_conn_t *conn;
} Sasldisc_t;

ssize_t sasl_read(Sfio_t *f, Void_t *buf, size_t size, Sfdisc_t *disc)
{
    int len, result;
    char *outbuf;
    int outlen;
    Sasldisc_t *sd = (Sasldisc_t *) disc;

    len = sfrd(f, buf, size, disc);

    if (len <= 0)
	return len;

    result = sasl_decode(sd->conn, buf, len, &outbuf, &outlen);

    if (result != SASL_OK) {
	/* eventually, we'll want an exception here */
	return -1;
    }

    if (outbuf != NULL) {
	memcpy(buf, outbuf, outlen);
	free(outbuf);
    }

    return outlen;
}

ssize_t sasl_write(Sfio_t *f, const Void_t *buf, size_t size, Sfdisc_t *disc)
{
    int result;
    char *outbuf;
    int outlen;
    Sasldisc_t *sd = (Sasldisc_t *) disc;

    result = sasl_encode(sd->conn, buf, size, &outbuf, &outlen);

    if (result != SASL_OK) {
	return -1;
    }

    if (outbuf != NULL) {
	sfwr(f, outbuf, outlen, disc);
	free(outbuf);
    }

    return size;
}

int sfdcsasl(Sfio_t *f, sasl_conn_t *conn)
{
    Sasldisc_t *sasl;
    
    if (conn == NULL) {
	/* no need to do anything */
	return 0;
    }

    if(!(sasl = (Sasldisc_t*)malloc(sizeof(Sasldisc_t))) )
	return -1;
    
    sasl->disc.readf = sasl_read;
    sasl->disc.writef = sasl_write;
    sasl->disc.seekf = NULL;
    sasl->disc.exceptf = NULL;

    sasl->conn = conn;

    if (sfdisc(f, (Sfdisc_t *) sasl) != (Sfdisc_t *) sasl) {
	free(sasl);
	return -1;
    }
    
    return 0;
}


