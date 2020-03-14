/* TBD, add (C) */

#include "t_common.h"

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <saslplug.h>

static int setup_socket(void)
{
    struct sockaddr_in addr;
    int sock, ret;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) s_error("socket", 0, 0, errno);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.9");
    addr.sin_port = htons(9000);

    ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret != 0) s_error("connect", 0, 0, errno);

    return sock;
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
    sasl_callback_t callbacks[2] = {};
    char buf[8192];
    const char *chosenmech;
    sasl_conn_t *conn;
    const char *data;
    unsigned int len;
    int sd;
    int r;

    /* initialize the sasl library */
    callbacks[0].id = SASL_CB_GETPATH;
    callbacks[0].proc = (sasl_callback_ft)&getpath;
    callbacks[0].context = NULL;
    callbacks[1].id = SASL_CB_LIST_END;
    callbacks[1].proc = NULL;
    callbacks[1].context = NULL;

    r = sasl_client_init(callbacks);
    if (r != SASL_OK) exit(-1);

    r = sasl_client_new("test", "host.realm.test", NULL, NULL, NULL, 0, &conn);
    if (r != SASL_OK) {
        saslerr(r, "allocating connection state");
        exit(-1);
    }

    r = sasl_client_start(conn, "GSSAPI", NULL, &data, &len, &chosenmech);
    if (r != SASL_OK && r != SASL_CONTINUE) {
	saslerr(r, "starting SASL negotiation");
	printf("\n%s\n", sasl_errdetail(conn));
	exit(-1);
    }

    sd = setup_socket();

    while (r == SASL_CONTINUE) {
        send_string(sd, data, len);
        len = 8192;
        recv_string(sd, buf, &len);

	r = sasl_client_step(conn, buf, len, NULL, &data, &len);
	if (r != SASL_OK && r != SASL_CONTINUE) {
	    saslerr(r, "performing SASL negotiation");
	    printf("\n%s\n", sasl_errdetail(conn));
	    exit(-1);
        }
    }

    if (r != SASL_OK) exit(-1);

    if (len > 0) {
        send_string(sd, data, len);
    }

    fprintf(stdout, "DONE\n");
    fflush(stdout);
    return 0;
}

