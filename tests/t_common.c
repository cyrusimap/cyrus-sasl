/* TBD, add (C) */

#include <t_common.h>

void s_error(const char *hdr, ssize_t ret, ssize_t len, int err)
{
    fprintf(stderr, "%s l:%ld/%ld [%d] %s",
            hdr, ret, len, err, strerror(err));
    exit(-1);
}

void send_string(int sd, const char *s, unsigned int l)
{
    ssize_t ret;

fprintf(stderr, "s:%u ", l);
fflush(stderr);

    ret = send(sd, &l, sizeof(l), 0);
    if (ret != sizeof(l)) s_error("send size", ret, sizeof(l), errno);

    if (l == 0) return;

    ret = send(sd, s, l, 0);
    if (ret != l) s_error("send data", ret, l, errno);
}

void recv_string(int sd, char *buf, unsigned int *buflen)
{
    unsigned int l;
    ssize_t ret;

    ret = recv(sd, &l, sizeof(l), MSG_WAITALL);
    if (ret != sizeof(l)) s_error("recv size", ret, sizeof(l), errno);

    if (l == 0) {
fprintf(stderr, "r:0 ");
fflush(stderr);
        *buflen = 0;
        return;
    }

    if (*buflen < l) s_error("recv len", l, *buflen, E2BIG);

    ret = recv(sd, buf, l, 0);
    if (ret != l) s_error("recv data", ret, l, errno);

fprintf(stderr, "r:%ld ", ret);
fflush(stderr);
    *buflen = ret;
}

void saslerr(int why, const char *what)
{
    fprintf(stderr, "%s: %s", what, sasl_errstring(why, NULL, NULL));
}

int getpath(void *context __attribute__((unused)), const char **path)
{
    if (! path) {
        return SASL_BADPARAM;
    }

    *path = PLUGINDIR;
    return SASL_OK;
}


