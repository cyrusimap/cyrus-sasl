#ifndef SFSASL_H
#define SFSASL_H

#include <sfio.h>

int sfdcsasl(Sfio_t *f, sasl_conn_t *conn);

#endif
