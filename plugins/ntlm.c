/* NTLM SASL plugin
 * Ken Murchison
 * $Id: ntlm.c,v 1.11 2003/08/26 20:57:58 ken3 Exp $
 *
 * References:
 *   http://www.innovation.ch/java/ntlm.html
 *   http://www.opengroup.org/comsource/techref2/NCH1222X.HTM
 *   http://www.ubiqx.org/cifs/rfc-draft/draft-leach-cifs-v1-spec-02.html
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>

#include <openssl/des.h>
#include <openssl/md4.h>

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

/*****************************  Common Section  *****************************/

static const char plugin_id[] = "$Id: ntlm.c,v 1.11 2003/08/26 20:57:58 ken3 Exp $";

#define NTLM_SIGNATURE		"NTLMSSP"

#define NTLM_USE_UNICODE	0x00001
#define NTLM_USE_ASCII		0x00002
#define NTLM_ASK_TARGET		0x00004
#define NTLM_AUTH_NTLM		0x00200
#define NTLM_ALWAYS_SIGN	0x08000
#define NTLM_TARGET_IS_DOMAIN	0x10000
#define NTLM_TARGET_IS_SERVER	0x20000
#define NTLM_FLAGS_MASK		0x0ffff

#define NTLM_NONCE_LENGTH	8
#define NTLM_HASH_LENGTH	21
#define NTLM_RESP_LENGTH	24
#define NTLM_SESSKEY_LENGTH	16

typedef unsigned short uint16;
typedef unsigned int   uint32;

typedef enum {
    NTLM_REQUEST   = 1,
    NTLM_CHALLENGE = 2,
    NTLM_RESPONSE  = 3
} ntlm_type_t;

typedef struct {
    uint16 len;
    uint16 maxlen;
    uint32 offset;
} ntlm_buffer_t;

typedef struct {
    u_char sig[sizeof(NTLM_SIGNATURE)];
    uint32 type;
    uint32 flags;
    ntlm_buffer_t domain;
    ntlm_buffer_t wkstn;
    /* buffer data follows */
} ntlm_request_t;

typedef struct {
    u_char sig[sizeof(NTLM_SIGNATURE)];
    uint32 type;
    ntlm_buffer_t domain;
    uint32 flags;
    u_char nonce[NTLM_NONCE_LENGTH];
    u_char reserved[8];
    ntlm_buffer_t empty;
    /* buffer data follows */
} ntlm_challenge_t;

typedef struct ntlm_response_s {
    u_char sig[sizeof(NTLM_SIGNATURE)];
    uint32 type;
    ntlm_buffer_t lm_resp;
    ntlm_buffer_t nt_resp;
    ntlm_buffer_t domain;
    ntlm_buffer_t user;
    ntlm_buffer_t wkstn;
    ntlm_buffer_t key;
    uint32 flags;
    /* buffer data follows */
} ntlm_response_t;

/* return the length of a string (even if it is NULL) */
#define xstrlen(s) (s ? strlen(s) : 0)

/* machine-independent routines to convert to/from Intel byte-order */
#define UINT16_TO_INTEL(x, i) \
    i = ((unsigned char *) &x)[0] | (((unsigned char *) &x)[1] << 8)

#define UINT16_FROM_INTEL(i, x) \
    ((unsigned char *) &x)[0] = i & 0xff; \
    ((unsigned char *) &x)[1] = (i >> 8)

#define UINT32_TO_INTEL(x, i) \
    i = ((unsigned char *) &x)[0] | (((unsigned char *) &x)[1] << 8) | \
	(((unsigned char *) &x)[2] << 16) | (((unsigned char *) &x)[3] << 24)

#define UINT32_FROM_INTEL(i, x) \
    ((unsigned char *) &x)[0] = i & 0xff; \
    ((unsigned char *) &x)[1] = (i >> 8) & 0xff; \
    ((unsigned char *) &x)[2] = (i >> 16) & 0xff; \
    ((unsigned char *) &x)[3] = (i >> 24)

/* convert string to all upper case */
static const char *ucase(const char *str, unsigned len)
{
    char *cp = (char *) str;

    if (!len) len = xstrlen(str);
    
    while (len && cp && *cp) {
	*cp = toupper((int) *cp);
	cp++;
	len--;
    }

    return (str);
}

/* copy src to dst as unicode (in Intel byte-order) */
static void to_unicode(u_char *dst, const char *src, int len)
{
    for (; len; len--) {
	*dst++ = *src++;
	*dst++ = 0;
    }
}

/* copy unicode src (in Intel byte-order) to dst */
static void from_unicode(char *dst, u_char *src, int len)
{
    for (; len; len--) {
	*dst++ = *src & 0x7f;
	src += 2;
    }
}

/* load a string into an NTLM buffer */
static void load_buffer(ntlm_buffer_t *buf, const u_char *str, uint16 len,
			int unicode, u_char *base, uint32 *offset)
{
    if (len) {
	if (unicode) {
	    to_unicode(base + *offset, str, len);
	    len *= 2;
	}
	else {
	    memcpy(base + *offset, str, len);
	}
    }

    UINT16_TO_INTEL(len, buf->len);
    buf->maxlen = buf->len;
    UINT32_TO_INTEL(*offset, buf->offset);
    *offset += len;
}

/* unload a string from an NTLM buffer */
static int unload_buffer(const sasl_utils_t *utils, ntlm_buffer_t *buf,
			 u_char **str, unsigned *outlen,
			 int unicode, u_char *base, unsigned msglen)
{
    uint16 len = 0;

    UINT16_FROM_INTEL(buf->len, len);

    if (len) {
	uint32 offset = 0;

	*str = utils->malloc(len + 1); /* add 1 for NUL */
	if (*str == NULL) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}

	UINT32_FROM_INTEL(buf->offset, offset);

	/* sanity check */
	if (offset > msglen || len > (msglen - offset)) return SASL_BADPROT;

	if (unicode) {
	    len /= 2;
	    from_unicode((char *) *str, base + offset, len);
	}
	else
	    memcpy(*str, base + offset, len);

	(*str)[len] = '\0'; /* add NUL */
    }
    else {
	*str = NULL;
    }

    if (outlen) *outlen = len;

    return SASL_OK;
}

/*
 * NTLM encryption/authentication routines per section 2.10 of
 * draft-leach-cifs-v1-spec-02
 */
static void E(unsigned char *out, unsigned char *K, unsigned Klen,
	      unsigned char *D, unsigned Dlen)
	      
{
    unsigned k, d;
    des_cblock K64;
    des_key_schedule ks;
    unsigned char *Dp;
#define KEY_SIZE   7
#define BLOCK_SIZE 8

    for (k = 0; k < Klen; k += KEY_SIZE, K += KEY_SIZE) {
	/* convert 56-bit key to 64-bit */
	K64[0] = K[0];
	K64[1] = ((K[0] << 7) & 0xFF) | (K[1] >> 1);
	K64[2] = ((K[1] << 6) & 0xFF) | (K[2] >> 2);
	K64[3] = ((K[2] << 5) & 0xFF) | (K[3] >> 3);
	K64[4] = ((K[3] << 4) & 0xFF) | (K[4] >> 4);
	K64[5] = ((K[4] << 3) & 0xFF) | (K[5] >> 5);
	K64[6] = ((K[5] << 2) & 0xFF) | (K[6] >> 6);
	K64[7] =  (K[6] << 1) & 0xFF;

 	des_set_odd_parity(&K64); /* XXX is this necessary? */
 	des_set_key(&K64, ks);

	for (d = 0, Dp = D; d < Dlen;
	     d += BLOCK_SIZE, Dp += BLOCK_SIZE, out += BLOCK_SIZE) {
 	    des_ecb_encrypt((void *) Dp, (void *) out, ks, DES_ENCRYPT);
	}
    }
}

static unsigned char *P16_lm(unsigned char *P16, const char *passwd)
{
    char P14[14];
    unsigned char S8[] = { 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };

    strncpy(P14, passwd, sizeof(P14));
    ucase(P14, sizeof(P14));

    E(P16, P14, sizeof(P14), S8, sizeof(S8));
    return P16;
}

static unsigned char *P16_nt(unsigned char *P16, const char *passwd)
{
    char U_PN[1024];

    to_unicode(U_PN, passwd, strlen(passwd));
    MD4(U_PN, 2 * strlen(passwd), P16);
    return P16;
}

static unsigned char *P21(unsigned char *P21, const char *passwd,
			  unsigned char* (*P16)(unsigned char *, const char *))
{
    memset(P16(P21, passwd) + 16, 0, 5);
    return P21;
}

static unsigned char *P24(unsigned char *P24, unsigned char *P21,
			  unsigned char *C8)
		      
{
    E(P24, P21, NTLM_HASH_LENGTH, C8, NTLM_NONCE_LENGTH);
    return P24;
}

/*****************************  Server Section  *****************************/

typedef struct server_context {
    int state;

    uint32 flags;
    unsigned char nonce[NTLM_NONCE_LENGTH];

    /* per-step mem management */
    char *out_buf;
    unsigned out_buf_len;

    /* socket to remote authentication host */
    int sock;

} server_context_t;

#define	N(a)			(sizeof (a) / sizeof (a[0]))

#define SMB_HDR_PROTOCOL	"\xffSMB"

typedef struct {
    unsigned char protocol[4];
    unsigned char command;
    uint32 status;
    unsigned char flags;
    uint16 flags2;
    unsigned char extra[12];
    uint16 tid;
    uint16 pid;
    uint16 uid;
    uint16 mid;
} SMB_Header;

typedef struct {
    uint16 dialect_index;
    unsigned char security_mode;
    uint16 max_mpx_count;
    uint16 max_number_vcs;
    uint32 max_buffer_size;
    uint32 max_raw_size;
    uint32 session_key;
    uint32 capabilities;
    uint32 system_time_low;
    uint32 system_time_high;
    uint16 server_time_zone;
    unsigned char encryption_key_length;
} SMB_NegProt_Resp;

typedef struct {
    unsigned char andx_command;
    unsigned char andx_reserved;
    uint16 andx_offset;
    uint16 max_buffer_size;
    uint16 max_mpx_count;
    uint16 vc_number;
    uint32 session_key;
    uint16 case_insensitive_passwd_len;
    uint16 case_sensitive_passwd_len;
    uint32 reserved;
    uint32 capabilities;
} SMB_SessionSetup;

typedef struct {
    unsigned char andx_command;
    unsigned char andx_reserved;
    uint16 andx_offset;
    uint16 action;
} SMB_SessionSetup_Resp;

enum {
    NBT_SESSION_REQUEST		= 0x81,
    NBT_POSITIVE_SESSION_RESP	= 0x82,
    NBT_NEGATIVE_SESSION_RESP	= 0x83,
    NBT_ERR_NO_LISTEN_CALLED	= 0x80,
    NBT_ERR_NO_LISTEN_CALLING	= 0x81,
    NBT_ERR_CALLED_NOT_PRESENT	= 0x82,
    NBT_ERR_INSUFFICIENT_RESRC	= 0x83,
    NBT_ERR_UNSPECIFIED		= 0x8F,

    SMB_HDR_SIZE		= 32,

    SMB_COM_NEGOTIATE_PROTOCOL	= 0x72,
    SMB_COM_SESSION_SETUP_ANDX	= 0x73,
    SMB_COM_NONE		= 0xFF,

    SMB_FLAGS_SERVER_TO_REDIR	= 0x80,

    SMB_FLAGS2_ERR_STATUS	= 0x4000,
    SMB_FLAGS2_UNICODE		= 0x8000,

    SMB_NEGPROT_RESP_SIZE	= 34,

    SMB_SECURITY_MODE_USER	= 0x1,
    SMB_SECURITY_MODE_ENCRYPT	= 0x2,
    SMB_SECURITY_MODE_SIGN	= 0x4,
    SMB_SECURITY_MODE_SIGN_REQ	= 0x8,

    SMB_CAP_UNICODE		= 0x0004,
    SMB_CAP_STATUS32		= 0x0040,
    SMB_CAP_EXTENDED_SECURITY	= 0x80000000,

    SMB_SESSION_SETUP_SIZE	= 26,
    SMB_SESSION_SETUP_RESP_SIZE	= 6,

    SMB_REQUEST_MODE_GUEST	= 0x1
};

static const char *SMB_DIALECTS[] = {
#if 0
    "\x02PC NETWORK PROGRAM 1.0",
    "\x02PCLAN1.0",
    "\x02MICROSOFT NETWORKS 1.03",
    "\x02MICROSOFT NETWORKS 3.0",
    "\x02LANMAN1.0",
    "\x02Windows for Workgroups 3.1a",
    "\x02LM1.2X002",
    "\x02DOS LM1.2X002",
    "\x02DOS LANLAM2.1",
    "\x02LANMAN2.1",
#endif
    "\x02NT LM 0.12"
};

static void load_smb_header(unsigned char buf[], SMB_Header *hdr)
{
    unsigned char *p = buf;

    memcpy(p, SMB_HDR_PROTOCOL, 4); p += 4;
    *p++ = hdr->command;
    UINT32_TO_INTEL(hdr->status, *((uint32*) p)); p += 4;
    *p++ = hdr->flags;
    UINT16_TO_INTEL(hdr->flags2, *((uint16*) p)); p += 2;
    memcpy(p, hdr->extra, 12); p += 12;
    UINT16_TO_INTEL(hdr->tid, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(hdr->pid, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(hdr->uid, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(hdr->mid, *((uint16*) p));
}

static void unload_smb_header(unsigned char buf[], SMB_Header *hdr)
{
    unsigned char *p = buf;

    memcpy(hdr->protocol, p, 4); p += 4;
    hdr->command = *p++;
    UINT32_FROM_INTEL(*((uint32*) p), hdr->status); p += 4;
    hdr->flags = *p++;
    UINT16_FROM_INTEL(*((uint16*) p), hdr->flags2); p += 2;
    memcpy(hdr->extra, p, 12); p += 12;
    UINT16_FROM_INTEL(*((uint16*) p), hdr->tid); p += 2;
    UINT16_FROM_INTEL(*((uint16*) p), hdr->pid); p += 2;
    UINT16_FROM_INTEL(*((uint16*) p), hdr->uid); p += 2;
    UINT16_FROM_INTEL(*((uint16*) p), hdr->mid);
}

static void unload_negprot_resp(unsigned char buf[], SMB_NegProt_Resp *resp)
{
    unsigned char *p = buf;

    UINT16_FROM_INTEL(*((uint16*) p), resp->dialect_index); p += 2;
    resp->security_mode = *p++;
    UINT16_FROM_INTEL(*((uint16*) p), resp->max_mpx_count); p += 2;
    UINT16_FROM_INTEL(*((uint16*) p), resp->max_number_vcs); p += 2;
    UINT32_FROM_INTEL(*((uint32*) p), resp->max_buffer_size); p += 4;
    UINT32_FROM_INTEL(*((uint32*) p), resp->max_raw_size); p += 4;
    UINT32_FROM_INTEL(*((uint32*) p), resp->session_key); p += 4;
    UINT32_FROM_INTEL(*((uint32*) p), resp->capabilities); p += 4;
    UINT32_FROM_INTEL(*((uint32*) p), resp->system_time_low); p += 4;
    UINT32_FROM_INTEL(*((uint32*) p), resp->system_time_high); p += 4;
    UINT16_FROM_INTEL(*((uint16*) p), resp->server_time_zone); p += 2;
    resp->encryption_key_length = *p;
}

static void load_session_setup(unsigned char buf[], SMB_SessionSetup *setup)
{
    unsigned char *p = buf;

    *p++ = setup->andx_command;
    *p++ = setup->andx_reserved;
    UINT16_TO_INTEL(setup->andx_offset, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(setup->max_buffer_size, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(setup->max_mpx_count, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(setup->vc_number, *((uint16*) p)); p += 2;
    UINT32_TO_INTEL(setup->session_key, *((uint32*) p)); p += 4;
    UINT16_TO_INTEL(setup->case_insensitive_passwd_len, *((uint16*) p)); p += 2;
    UINT16_TO_INTEL(setup->case_sensitive_passwd_len, *((uint16*) p)); p += 2;
    UINT32_TO_INTEL(setup->reserved, *((uint32*) p)); p += 4;
    UINT32_TO_INTEL(setup->capabilities, *((uint32*) p));
}

static void unload_session_setup_resp(unsigned char buf[],
				      SMB_SessionSetup_Resp *resp)
{
    unsigned char *p = buf;

    resp->andx_command = *p++;
    resp->andx_reserved = *p++;
    UINT16_FROM_INTEL(*((uint16*) p), resp->andx_offset); p += 2;
    UINT16_FROM_INTEL(*((uint16*) p), resp->action);
}

/*
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 */
static int retry_writev(int fd, struct iovec *iov, int iovcnt)
{
    int n;
    int i;
    int written = 0;
    static int iov_max =
#ifdef MAXIOV
	MAXIOV
#else
#ifdef IOV_MAX
	IOV_MAX
#else
	8192
#endif
#endif
	;
    
    for (;;) {
	while (iovcnt && iov[0].iov_len == 0) {
	    iov++;
	    iovcnt--;
	}

	if (!iovcnt) return written;

	n = writev(fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
	if (n == -1) {
	    if (errno == EINVAL && iov_max > 10) {
		iov_max /= 2;
		continue;
	    }
	    if (errno == EINTR) continue;
	    return -1;
	}

	written += n;

	for (i = 0; i < iovcnt; i++) {
	    if (iov[i].iov_len > (unsigned) n) {
		iov[i].iov_base = (char *)iov[i].iov_base + n;
		iov[i].iov_len -= n;
		break;
	    }
	    n -= iov[i].iov_len;
	    iov[i].iov_len = 0;
	}

	if (i == iovcnt) return written;
    }
}

static void make_netbios_name(const char *in, unsigned char out[])
{
    size_t i, j = 0, n;

    /* create a NetBIOS name from the DNS name
     *
     * - use up to the first 16 chars of the first part of the hostname
     * - convert to all uppercase
     * - use the tail end of the output buffer as temp space
     */
    n = strcspn(in, ".");
    if (n > 16) n = 16;
    strncpy(out+18, in, n);
    in = out+18;
    ucase(in, n);

    out[j++] = 0x20;
    for (i = 0; i < n; i++) {
	out[j++] = ((in[i] >> 4) & 0xf) + 0x41;
	out[j++] = (in[i] & 0xf) + 0x41;
    }
    for (; i < 16; i++) {
	out[j++] = ((0x20 >> 4) & 0xf) + 0x41;
	out[j++] = (0x20 & 0xf) + 0x41;
    }
    out[j] = 0;
}

static int smb_connect_server(const sasl_utils_t *utils, const char *client,
			      const char *server)
{
    struct addrinfo hints;
    struct addrinfo *ai = NULL, *r;
    int s = -1, err, saved_errno;
    char *port = "139";
    char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];

    unsigned char called[34];
    unsigned char calling[34];
    struct iovec iov[3];
    uint32 pkt;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if ((err = getaddrinfo(server, port, &hints, &ai)) != 0) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: getaddrinfo %s/%s: %s",
		   server, port, gai_strerror(err));
	return -1;
    }

    /* Make sure we have AF_INET or AF_INET6 addresses. */
    if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
	utils->log(NULL, SASL_LOG_ERR, "NTLM: no IP address info for %s",
		   ai->ai_canonname ? ai->ai_canonname : server);
	freeaddrinfo(ai);
	return -1;
    }

    /* establish connection to authentication server */
    for (r = ai; r; r = r->ai_next) {
	s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
	if (s < 0)
	    continue;
	if (connect(s, r->ai_addr, r->ai_addrlen) >= 0)
	    break;
	close(s);
	s = -1;
	saved_errno = errno;
	getnameinfo(r->ai_addr, r->ai_addrlen,
		    hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
		    NI_NUMERICHOST | NI_WITHSCOPEID | NI_NUMERICSERV);
	errno = saved_errno;
	utils->log(NULL, SASL_LOG_WARN, "NTLM: connect %s[%s]/%s: %m",
		   ai->ai_canonname ? ai->ai_canonname : server, hbuf, pbuf);
    }
    if (s < 0) {
	getnameinfo(ai->ai_addr, ai->ai_addrlen, NULL, 0,
			pbuf, sizeof(pbuf), NI_NUMERICSERV);
	utils->log(NULL, SASL_LOG_ERR, "NTLM: couldn't connect to %s/%s",
		   ai->ai_canonname ? ai->ai_canonname : server, pbuf);
	freeaddrinfo(ai);
	return -1;
    }

    freeaddrinfo(ai);

    /*** send NetBIOS session request ***/

    /* get length of data */
    pkt = sizeof(called) + sizeof(calling);

    /* make sure length is less than 17 bits */
    if (pkt >= (1 << 17)) {
	close(s);
	return -1;
    }

    /* prepend the packet type */
    pkt |= (NBT_SESSION_REQUEST << 24);
    pkt = htonl(pkt);

    /* XXX should determine the real NetBIOS name */
    make_netbios_name(server, called);
    make_netbios_name(client, calling);

    iov[0].iov_base = &pkt;
    iov[0].iov_len = sizeof(pkt);
    iov[1].iov_base = called;
    iov[1].iov_len = sizeof(called);
    iov[2].iov_base = calling;
    iov[2].iov_len = sizeof(calling);

    rc = retry_writev(s, iov, N(iov));
    if (rc == -1) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error sending NetBIOS session request");
	close(s);
	return -1;
    }

    rc = read(s, &pkt, sizeof(pkt));
    pkt = ntohl(pkt);
    if (rc == -1 || pkt != (uint32) (NBT_POSITIVE_SESSION_RESP << 24)) {
	unsigned char ec = NBT_ERR_UNSPECIFIED;
	char *errstr;

	read(s, &ec, sizeof(ec));
	switch (ec) {
	case NBT_ERR_NO_LISTEN_CALLED:
	    errstr = "Not listening on called name";
	    break;
	case NBT_ERR_NO_LISTEN_CALLING:
	    errstr = "Not listening for calling name";
	    break;
	case NBT_ERR_CALLED_NOT_PRESENT:
	    errstr = "Called name not present";
	    break;
	case NBT_ERR_INSUFFICIENT_RESRC:
	    errstr = "Called name present, but insufficient resources";
	    break;
	default:
	    errstr = "Unspecified error";
	}
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: negative NetBIOS session response: %s", errstr);
	close(s);
	return -1;
    }

    return s;
}

static int smb_negotiate_protocol(const sasl_utils_t *utils,
				  server_context_t *text, char **domain)
{
    SMB_Header hdr;
    SMB_NegProt_Resp resp;
    unsigned char hbuf[SMB_HDR_SIZE], *p;
    unsigned char wordcount = 0;
    uint16 bytecount, bc;
    uint32 len, nl;
    struct iovec iov[4+N(SMB_DIALECTS)];
    size_t i, n;
    int rc;

    /*** create a negotiate protocol request ***/

    /* create a header */
    memset(&hdr, 0, sizeof(hdr));
    hdr.command = SMB_COM_NEGOTIATE_PROTOCOL;
#if 0
    hdr.flags2 = SMB_FLAGS2_ERR_STATUS;
    if (text->flags & NTLM_USE_UNICODE) hdr.flags2 |= SMB_FLAGS2_UNICODE;
#endif
    hdr.pid = getpid();
    load_smb_header(hbuf, &hdr);

    /* put together all of the pieces of the request */
    n = 0;
    iov[n].iov_base = &nl;
    iov[n++].iov_len = sizeof(len);
    iov[n].iov_base = hbuf;
    iov[n++].iov_len = SMB_HDR_SIZE;
    iov[n].iov_base = &wordcount;
    iov[n++].iov_len = sizeof(wordcount);
    iov[n].iov_base = &bc;
    iov[n++].iov_len = sizeof(bc);

    /* add our supported dialects */
    for (i = 0; i < N(SMB_DIALECTS); i++) {
	iov[n].iov_base = (char *) SMB_DIALECTS[i];
	iov[n++].iov_len = strlen(SMB_DIALECTS[i]) + 1;
    }

    /* total up the lengths */
    len = bytecount = 0;
    for (i = 1; i < 4; i++) len += iov[i].iov_len;
    for (i = 4; i < n; i++) bytecount += iov[i].iov_len;
    len += bytecount;
    nl = htonl(len);
    UINT16_TO_INTEL(bytecount, bc);

    /* send it */
    rc = retry_writev(text->sock, iov, n);
    if (rc == -1) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error sending NEGPROT request");
	return SASL_FAIL;
    }

    /*** read the negotiate protocol response ***/

    /* read the total length */
    rc = read(text->sock, &nl, sizeof(nl));
    if (rc < (int) sizeof(nl)) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error reading NEGPROT response length");
	return SASL_FAIL;
    }

    /* read the data */
    len = ntohl(nl);
    if (_plug_buf_alloc(utils, &text->out_buf, &text->out_buf_len,
			len) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM NEGPROT response buffer");
	return SASL_NOMEM;
    }

    rc = read(text->sock, text->out_buf, len);
    if (rc < (int) len) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error reading NEGPROT response");
	return SASL_FAIL;
    }
    p = text->out_buf;

    /* parse the header */
    if (len < SMB_HDR_SIZE) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: not enough data for NEGPROT response header");
	return SASL_FAIL;
    }
    unload_smb_header(p, &hdr);
    p += SMB_HDR_SIZE;
    len -= SMB_HDR_SIZE;

    /* sanity check the header */
    if (memcmp(hdr.protocol, SMB_HDR_PROTOCOL, 4)	 /* correct protocol */
	|| hdr.command != SMB_COM_NEGOTIATE_PROTOCOL /* correct command */
	|| hdr.status				 /* no errors */
	|| !(hdr.flags & SMB_FLAGS_SERVER_TO_REDIR)) { /* response */
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error in NEGPROT response header: %ld",
		   hdr.status);
	return SASL_FAIL;
    }

    /* get the wordcount */
    if (len < 1) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: not enough data for NEGPROT response wordcount");
	return SASL_FAIL;
    }
    wordcount = *p++;
    len--;

    /* parse the parameters */
    if (wordcount != SMB_NEGPROT_RESP_SIZE / sizeof(uint16)) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: incorrect NEGPROT wordcount for NT LM 0.12");
	return SASL_FAIL;
    }
    unload_negprot_resp(p, &resp);
    p += SMB_NEGPROT_RESP_SIZE;
    len -= SMB_NEGPROT_RESP_SIZE;

    /* sanity check the parameters */
    if (resp.dialect_index != 0
	|| !(resp.security_mode & SMB_SECURITY_MODE_USER)
	|| !(resp.security_mode & SMB_SECURITY_MODE_ENCRYPT)
	|| resp.security_mode & SMB_SECURITY_MODE_SIGN_REQ
	|| resp.capabilities & SMB_CAP_EXTENDED_SECURITY
	|| resp.encryption_key_length != NTLM_NONCE_LENGTH) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error in NEGPROT response parameters");
	return SASL_FAIL;
    }

    /* get the bytecount */
    if (len < 2) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: not enough data for NEGPROT response bytecount");
	return SASL_FAIL;
    }
    UINT16_FROM_INTEL(*((uint16*) p), bytecount);
    p += 2;
    len -= 2;
    if (len != bytecount) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: incorrect bytecount for NEGPROT response data");
	return SASL_FAIL;
    }

    /* parse the data */
    memcpy(text->nonce, p, resp.encryption_key_length);
    p += resp.encryption_key_length;
    len -= resp.encryption_key_length;

    /* if client asked for target, send domain */
    if (text->flags & NTLM_ASK_TARGET) {
	*domain = utils->malloc(len);
	if (domain == NULL) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	memcpy(*domain, p, len);
	from_unicode(*domain, *domain, len);

	text->flags |= NTLM_TARGET_IS_DOMAIN;
    }

    return SASL_OK;
}

static int smb_session_setup(const sasl_utils_t *utils, server_context_t *text,
			     const char *authid, char *domain,
			     unsigned char *lm_resp, unsigned char *nt_resp)
{
    SMB_Header hdr;
    SMB_SessionSetup setup;
    SMB_SessionSetup_Resp resp;
    unsigned char hbuf[SMB_HDR_SIZE], sbuf[SMB_SESSION_SETUP_SIZE], *p;
    unsigned char wordcount = SMB_SESSION_SETUP_SIZE / sizeof(uint16);
    uint16 bytecount, bc;
    uint32 len, nl;
    struct iovec iov[12];
    size_t i, n;
    int rc;
    struct utsname os;
    char osbuf[2*SYS_NMLN+2], lanman[20];

    /*** create a session setup request ***/

    /* create a header */
    memset(&hdr, 0, sizeof(hdr));
    hdr.command = SMB_COM_SESSION_SETUP_ANDX;
#if 0
    hdr.flags2 = SMB_FLAGS2_ERR_STATUS;
    if (text->flags & NTLM_USE_UNICODE) hdr.flags2 |= SMB_FLAGS2_UNICODE;
#endif
    hdr.pid = getpid();
    load_smb_header(hbuf, &hdr);

    /* create a the setup parameters */
    memset(&setup, 0, sizeof(setup));
    setup.andx_command = SMB_COM_NONE;
    setup.max_buffer_size = 0xFFFF;
    if (lm_resp) setup.case_insensitive_passwd_len = NTLM_RESP_LENGTH;
    if (nt_resp) setup.case_sensitive_passwd_len = NTLM_RESP_LENGTH;
#if 0
    if (text->flags & NTLM_USE_UNICODE)
	setup.capabilities = SMB_CAP_UNICODE;
#endif
    load_session_setup(sbuf, &setup);

    uname(&os);
    snprintf(osbuf, sizeof(osbuf), "%s %s", os.sysname, os.release);

    snprintf(lanman, sizeof(lanman), "Cyrus SASL %u.%u.%u",
	     SASL_VERSION_MAJOR, SASL_VERSION_MINOR,
	     SASL_VERSION_STEP);

    /* put together all of the pieces of the request */
    n = 0;
    iov[n].iov_base = &nl;
    iov[n++].iov_len = sizeof(len);
    iov[n].iov_base = hbuf;
    iov[n++].iov_len = SMB_HDR_SIZE;
    iov[n].iov_base = &wordcount;
    iov[n++].iov_len = sizeof(wordcount);
    iov[n].iov_base = sbuf;
    iov[n++].iov_len = SMB_SESSION_SETUP_SIZE;
    iov[n].iov_base = &bc;
    iov[n++].iov_len = sizeof(bc);
    if (lm_resp) {
	iov[n].iov_base = lm_resp;
	iov[n++].iov_len = NTLM_RESP_LENGTH;
    }
    if (nt_resp) {
	iov[n].iov_base = nt_resp;
	iov[n++].iov_len = NTLM_RESP_LENGTH;
    }
    iov[n].iov_base = (char*) authid;
    iov[n++].iov_len = strlen(authid) + 1;
    iov[n].iov_base = domain;
    iov[n++].iov_len = strlen(domain) + 1;
    iov[n].iov_base = osbuf;
    iov[n++].iov_len = strlen(osbuf) + 1;
    iov[n].iov_base = lanman;
    iov[n++].iov_len = strlen(lanman) + 1;

    /* total up the lengths */
    len = bytecount = 0;
    for (i = 1; i < 5; i++) len += iov[i].iov_len;
    for (i = 5; i < n; i++) bytecount += iov[i].iov_len;
    len += bytecount;
    nl = htonl(len);
    UINT16_TO_INTEL(bytecount, bc);

    /* send it */
    rc = retry_writev(text->sock, iov, n);
    if (rc == -1) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error sending SESSIONSETUP request");
	return SASL_FAIL;
    }

    /*** read the session setup response ***/

    /* read the total length */
    rc = read(text->sock, &nl, sizeof(nl));
    if (rc < (int) sizeof(nl)) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error reading SESSIONSETUP response length");
	return SASL_FAIL;
    }

    /* read the data */
    len = ntohl(nl);
    if (_plug_buf_alloc(utils, &text->out_buf, &text->out_buf_len,
			len) != SASL_OK) {
	SETERROR(utils,
		 "cannot allocate NTLM SESSIONSETUP response buffer");
	return SASL_NOMEM;
    }

    rc = read(text->sock, text->out_buf, len);
    if (rc < (int) len) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error reading SESSIONSETUP response");
	return SASL_FAIL;
    }
    p = text->out_buf;

    /* parse the header */
    if (len < SMB_HDR_SIZE) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: not enough data for SESSIONSETUP response header");
	return SASL_FAIL;
    }
    unload_smb_header(p, &hdr);
    p += SMB_HDR_SIZE;
    len -= SMB_HDR_SIZE;

    /* sanity check the header */
    if (memcmp(hdr.protocol, SMB_HDR_PROTOCOL, 4)	 /* correct protocol */
	|| hdr.command != SMB_COM_SESSION_SETUP_ANDX /* correct command */
	|| !(hdr.flags & SMB_FLAGS_SERVER_TO_REDIR)) { /* response */
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: error in SESSIONSETUP response header");
	return SASL_FAIL;
    }

    /* check auth success */
    if (hdr.status) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: auth failure: %ld", hdr.status);
	return SASL_BADAUTH;
    }

    /* get the wordcount */
    if (len < 1) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: not enough data for SESSIONSETUP response wordcount");
	return SASL_FAIL;
    }
    wordcount = *p++;
    len--;

    /* parse the parameters */
    if (wordcount < SMB_SESSION_SETUP_RESP_SIZE / sizeof(uint16)) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: incorrect SESSIONSETUP wordcount");
	return SASL_FAIL;
    }
    unload_session_setup_resp(p, &resp);

    /* check auth success */
    if (resp.action & SMB_REQUEST_MODE_GUEST) {
	utils->log(NULL, SASL_LOG_ERR,
		   "NTLM: authenticated as guest");
	return SASL_BADAUTH;
    }

    return SASL_OK;
}

static int create_challenge(const sasl_utils_t *utils,
			    server_context_t *text,
			    const char *domain,
			    uint32 flags,
			    const u_char *nonce,
			    unsigned *outlen)
{
    ntlm_challenge_t *chal;
    uint32 type = NTLM_CHALLENGE;
    uint32 offset = sizeof(ntlm_challenge_t);

    if (!nonce) {
	SETERROR(utils, "need nonce for NTLM challenge");
	return SASL_FAIL;
    }

    *outlen = sizeof(ntlm_challenge_t) + 2*xstrlen(domain);

    if (_plug_buf_alloc(utils, &text->out_buf, &text->out_buf_len,
			*outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM challenge");
	return SASL_NOMEM;
    }
    
    chal = (ntlm_challenge_t *) text->out_buf;
    memcpy(chal->sig, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    UINT32_TO_INTEL(type, chal->type);

    load_buffer(&chal->domain, ucase(domain, 0), xstrlen(domain),
		flags & NTLM_USE_UNICODE, (u_char *) chal, &offset);
    UINT32_TO_INTEL(flags, chal->flags);
    memcpy(chal->nonce, nonce, NTLM_NONCE_LENGTH);

    return SASL_OK;
}

static int ntlm_server_mech_new(void *glob_context __attribute__((unused)), 
				sasl_server_params_t *sparams,
				const char *challenge __attribute__((unused)),
				unsigned challen __attribute__((unused)),
				void **conn_context)
{
    server_context_t *text;
    const char *serv;
    unsigned int len;
    int sock = -1;

    sparams->utils->getopt(sparams->utils->getopt_context,
			   "NTLM", "ntlm_server", &serv, &len);
    if (serv) {
	/* try to start a NetBIOS session with the server */
	sock = smb_connect_server(sparams->utils, sparams->serverFQDN, serv);
	if (sock == -1) return SASL_UNAVAIL;
    }
    
    /* holds state are in */
    text = sparams->utils->malloc(sizeof(server_context_t));
    if (text == NULL) {
	MEMERROR( sparams->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(server_context_t));
    
    text->state = 1;
    text->sock = sock;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int ntlm_server_mech_step1(server_context_t *text,
				  sasl_server_params_t *sparams,
				  const char *clientin,
				  unsigned clientinlen,
				  const char **serverout,
				  unsigned *serveroutlen,
				  sasl_out_params_t *oparams __attribute__((unused)))
{
    ntlm_request_t *request = (ntlm_request_t *) clientin;
    char *domain = NULL;
    int result;

    if (!request || clientinlen < sizeof(ntlm_request_t)) {
	SETERROR(sparams->utils, "client didn't issue valid NTLM request");
	return SASL_BADPROT;
    }

    UINT32_FROM_INTEL(request->flags, text->flags);
    sparams->utils->log(NULL, SASL_LOG_DEBUG,
			"client flags: %x", text->flags);

    text->flags &= NTLM_FLAGS_MASK; /* mask off the bits we don't support */

    /* if client can do Unicode, turn off ASCII */
    if (text->flags & NTLM_USE_UNICODE) text->flags &= ~NTLM_USE_ASCII;

    if (text->sock == -1) {
	/* generate challenge internally */

	/* if client asked for target, use FQDN as server target */
	if (text->flags & NTLM_ASK_TARGET) {
	    result = _plug_strdup(sparams->utils, sparams->serverFQDN,
			      &domain, NULL);
	    if (result != SASL_OK) return result;

	    text->flags |= NTLM_TARGET_IS_SERVER;
	}

	/* generate a nonce */
	sparams->utils->rand(sparams->utils->rpool,
			     (char *) text->nonce, NTLM_NONCE_LENGTH);
    }
    else {
	/* proxy the response/challenge */
	result = smb_negotiate_protocol(sparams->utils, text, &domain);
	if (result != SASL_OK) goto cleanup;
    }

    result = create_challenge(sparams->utils, text, domain, text->flags,
			      text->nonce, serveroutlen);
    if (result != SASL_OK) goto cleanup;

    *serverout = text->out_buf;

    text->state = 2;
    
    result = SASL_CONTINUE;

  cleanup:
    if (domain) sparams->utils->free(domain);

    return result;
}

static int ntlm_server_mech_step2(server_context_t *text,
				  sasl_server_params_t *sparams,
				  const char *clientin,
				  unsigned clientinlen,
				  const char **serverout __attribute__((unused)),
				  unsigned *serveroutlen __attribute__((unused)),
				  sasl_out_params_t *oparams)
{
    ntlm_response_t *response = (ntlm_response_t *) clientin;
    unsigned char *lm_resp_c = NULL, *nt_resp_c = NULL;
    char *domain = NULL, *authid = NULL;
    unsigned lm_resp_len, nt_resp_len, domain_len, authid_len;
    int result;

    if (!response || clientinlen < sizeof(ntlm_response_t)) {
	SETERROR(sparams->utils, "client didn't issue valid NTLM response");
	return SASL_BADPROT;
    }

    result = unload_buffer(sparams->utils, &response->lm_resp,
			   (u_char **) &lm_resp_c, &lm_resp_len, 0,
			   (u_char *) response, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, &response->nt_resp,
			   (u_char **) &nt_resp_c, &nt_resp_len, 0,
			   (u_char *) response, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, &response->domain,
			   (u_char **) &domain, &domain_len,
			   text->flags & NTLM_USE_UNICODE,
			   (u_char *) response, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, &response->user,
			   (u_char **) &authid, &authid_len,
			   text->flags & NTLM_USE_UNICODE,
			   (u_char *) response, clientinlen);
    if (result != SASL_OK) goto cleanup;

    /* require at least one response and an authid */
    if ((!lm_resp_c && !nt_resp_c) ||
	(lm_resp_c && lm_resp_len < NTLM_RESP_LENGTH) ||
	(nt_resp_c && nt_resp_len < NTLM_RESP_LENGTH) ||
	!authid) {
	SETERROR(sparams->utils, "client issued incorrect/nonexistent responses");
	result = SASL_BADPROT;
	goto cleanup;
    }

    if (text->sock == -1) {
	/* verify the response internally */

	sasl_secret_t *password = NULL;
	unsigned pass_len;
	const char *password_request[] = { SASL_AUX_PASSWORD,
				       NULL };
	struct propval auxprop_values[2];
	unsigned char hash[NTLM_HASH_LENGTH];
	unsigned char lm_resp_s[NTLM_RESP_LENGTH], nt_resp_s[NTLM_RESP_LENGTH];

	/* fetch user's password */
	result = sparams->utils->prop_request(sparams->propctx, password_request);
	if (result != SASL_OK) goto cleanup;
    
	/* this will trigger the getting of the aux properties */
	result = sparams->canon_user(sparams->utils->conn, authid, authid_len,
				     SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) goto cleanup;

	result = sparams->utils->prop_getnames(sparams->propctx,
					       password_request,
					       auxprop_values);
	if (result < 0 ||
	    (!auxprop_values[0].name || !auxprop_values[0].values)) {
	    /* We didn't find this username */
	    SETERROR(sparams->utils, "no secret in database");
	    result = SASL_NOUSER;
	    goto cleanup;
	}
    
	pass_len = strlen(auxprop_values[0].values[0]);
	if (pass_len == 0) {
	    SETERROR(sparams->utils, "empty secret");
	    result = SASL_FAIL;
	    goto cleanup;
	}

	password = sparams->utils->malloc(sizeof(sasl_secret_t) + pass_len);
	if (!password) {
	    result = SASL_NOMEM;
	    goto cleanup;
	}
	
	password->len = pass_len;
	strncpy(password->data, auxprop_values[0].values[0], pass_len + 1);

	/* calculate our own responses */
	P24(lm_resp_s, P21(hash, password->data, P16_lm), text->nonce);
	P24(nt_resp_s, P21(hash, password->data, P16_nt), text->nonce);

	_plug_free_secret(sparams->utils, &password);

	/* compare client's responses with ours */
	if ((lm_resp_c && memcmp(lm_resp_c, lm_resp_s, NTLM_RESP_LENGTH)) ||
	    (nt_resp_c && memcmp(nt_resp_c, nt_resp_s, NTLM_RESP_LENGTH))) {
	    SETERROR(sparams->utils, "incorrect NTLM responses");
	    result = SASL_BADAUTH;
	    goto cleanup;
	}
    }
    else {
	/* proxy the response */
	result = smb_session_setup(sparams->utils, text, authid,
				   domain, lm_resp_c, nt_resp_c);
	if (result != SASL_OK) goto cleanup;

	result = sparams->canon_user(sparams->utils->conn, authid, authid_len,
				     SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) goto cleanup;
    }

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    result = SASL_OK;

  cleanup:
    if (lm_resp_c) sparams->utils->free(lm_resp_c);
    if (nt_resp_c) sparams->utils->free(nt_resp_c);
    if (domain) sparams->utils->free(domain);
    if (authid) sparams->utils->free(authid);

    return result;
}

static int ntlm_server_mech_step(void *conn_context,
				 sasl_server_params_t *sparams,
				 const char *clientin,
				 unsigned clientinlen,
				 const char **serverout,
				 unsigned *serveroutlen,
				 sasl_out_params_t *oparams)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    *serverout = NULL;
    *serveroutlen = 0;
    
    sparams->utils->log(NULL, SASL_LOG_DEBUG,
		       "NTLM server step %d\n", text->state);

    switch (text->state) {
	
    case 1:
	return ntlm_server_mech_step1(text, sparams, clientin, clientinlen,
				      serverout, serveroutlen, oparams);
	
    case 2:
	return ntlm_server_mech_step2(text, sparams, clientin, clientinlen,
				      serverout, serveroutlen, oparams);
	
    default:
	sparams->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid NTLM server step %d\n", text->state);
	return SASL_FAIL;
    }
    
    return SASL_FAIL; /* should never get here */
}

static void ntlm_server_mech_dispose(void *conn_context,
				     const sasl_utils_t *utils)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);
    if (text->sock != -1) close(text->sock);

    utils->free(text);
}

static sasl_server_plug_t ntlm_server_plugins[] = 
{
    {
	"NTLM",				/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
	NULL,				/* glob_context */
	&ntlm_server_mech_new,		/* mech_new */
	&ntlm_server_mech_step,		/* mech_step */
	&ntlm_server_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech_avail */
	NULL				/* spare */
    }
};

int ntlm_server_plug_init(sasl_utils_t *utils,
			  int maxversion,
			  int *out_version,
			  sasl_server_plug_t **pluglist,
			  int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = ntlm_server_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    int state;

    /* per-step mem management */
    char *out_buf;
    unsigned out_buf_len;

} client_context_t;

static int create_request(const sasl_utils_t *utils,
			  client_context_t *text,
			  const char *domain, const char *wkstn,
			  unsigned *outlen)
{
    ntlm_request_t *req;
    uint32 type = NTLM_REQUEST;
    uint32 flags = (NTLM_USE_UNICODE | NTLM_USE_ASCII | 
		    NTLM_ASK_TARGET | NTLM_AUTH_NTLM);
    uint32 offset = sizeof(ntlm_request_t);

    *outlen = sizeof(ntlm_request_t) + xstrlen(domain) + xstrlen(wkstn);
    if (_plug_buf_alloc(utils, &text->out_buf, &text->out_buf_len,
			*outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM request");
	return SASL_NOMEM;
    }
    
    req = (ntlm_request_t *) text->out_buf;
    memcpy(req->sig, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    UINT32_TO_INTEL(type, req->type);
    UINT32_TO_INTEL(flags, req->flags);

    load_buffer(&req->domain, domain, xstrlen(domain), 0,
		(u_char *) req, &offset);
    load_buffer(&req->wkstn, wkstn, xstrlen(wkstn), 0,
		(u_char *) req, &offset);

    return SASL_OK;
}

static int create_response(const sasl_utils_t *utils,
			   client_context_t *text,
			   const u_char *lm_resp,
			   const u_char *nt_resp,
			   const char *domain, const char *user,
			   const char *wkstn, const u_char *key,
			   uint32 flags,
			   unsigned *outlen)
{
    ntlm_response_t *resp;
    uint32 type = NTLM_RESPONSE;
    uint32 offset = sizeof(ntlm_response_t);

    if (!lm_resp && !nt_resp) {
	SETERROR(utils, "need at least one NT/LM response");
	return SASL_FAIL;
    }

    *outlen = sizeof(ntlm_response_t) + 2*xstrlen(domain) +
	2*xstrlen(user) + 2*xstrlen(wkstn);
    if (lm_resp) *outlen += NTLM_RESP_LENGTH;
    if (nt_resp) *outlen += NTLM_RESP_LENGTH;
    if (key) *outlen += NTLM_SESSKEY_LENGTH;

    if (_plug_buf_alloc(utils, &text->out_buf, &text->out_buf_len,
			*outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM response");
	return SASL_NOMEM;
    }
    
    resp = (ntlm_response_t *) text->out_buf;
    memcpy(resp->sig, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    UINT32_TO_INTEL(type, resp->type);

    load_buffer(&resp->lm_resp, lm_resp, lm_resp ? NTLM_RESP_LENGTH : 0, 0,
		(u_char *) resp, &offset);
    load_buffer(&resp->nt_resp, nt_resp, nt_resp ? NTLM_RESP_LENGTH : 0, 0,
		(u_char *) resp, &offset);
    load_buffer(&resp->domain, ucase(domain, 0), xstrlen(domain),
		flags & NTLM_USE_UNICODE,
		(u_char *) resp, &offset);
    load_buffer(&resp->user, user, xstrlen(user),
		flags & NTLM_USE_UNICODE,
		(u_char *) resp, &offset);
    load_buffer(&resp->wkstn, ucase(wkstn, 0), xstrlen(wkstn),
		flags & NTLM_USE_UNICODE,
		(u_char *) resp, &offset);
    load_buffer(&resp->key, key, key ? NTLM_SESSKEY_LENGTH : 0, 0,
		(u_char *) resp, &offset);

    UINT32_TO_INTEL(flags, resp->flags);

    return SASL_OK;
}

static int ntlm_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn_context)
{
    client_context_t *text;
    
    /* holds state are in */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(client_context_t));
    
    text->state = 1;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int ntlm_client_mech_step1(client_context_t *text,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need __attribute__((unused)),
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams __attribute__((unused)))
{
    int result;
    
    /* check if sec layer strong enough */
    if (params->props.min_ssf > params->external_ssf) {
	SETERROR(params->utils, "SSF requested of NTLM plugin");
	return SASL_TOOWEAK;
    }

    /* we don't care about domain or wkstn */
    result = create_request(params->utils, text, NULL, NULL, clientoutlen);
    if (result != SASL_OK) return result;

    *clientout = text->out_buf;
    
    text->state = 2;
    
    return SASL_CONTINUE;
}

static int ntlm_client_mech_step2(client_context_t *text,
				  sasl_client_params_t *params,
				  const char *serverin,
				  unsigned serverinlen,
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
    ntlm_challenge_t *challenge = (ntlm_challenge_t *) serverin;
    const char *authid = NULL;
    sasl_secret_t *password = NULL;
    unsigned int free_password; /* set if we need to free password */
    char *domain = NULL;
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    uint32 flags = 0;
    unsigned char hash[NTLM_HASH_LENGTH];
    unsigned char resp[NTLM_RESP_LENGTH], *lm_resp = NULL, *nt_resp = NULL;
    int result;

    if (!challenge || serverinlen < sizeof(ntlm_challenge_t)) {
	SETERROR(params->utils, "server didn't issue valid NTLM challenge");
	return SASL_BADPROT;
    }

    /* try to get the authid */
    if (oparams->authid == NULL) {
	auth_result = _plug_get_authid(params->utils, &authid, prompt_need);
	
	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	    return auth_result;
    }
    
    /* try to get the password */
    if (password == NULL) {
	pass_result = _plug_get_password(params->utils, &password,
					 &free_password, prompt_need);
	
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	    return pass_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }
    
    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) || (pass_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
	    _plug_make_prompts(params->utils, prompt_need,
			       NULL, NULL,
			       auth_result == SASL_INTERACT ?
			       "Please enter your authentication name" : NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       "Please enter your password" : NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
	if (result != SASL_OK) goto cleanup;
	
	return SASL_INTERACT;
    }
    
    result = params->canon_user(params->utils->conn, authid, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto cleanup;

    UINT32_FROM_INTEL(challenge->flags, flags);
    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "server flags: %x", flags);

    flags &= NTLM_FLAGS_MASK; /* mask off the bits we don't support */

    result = unload_buffer(params->utils, &challenge->domain,
			   (u_char **) &domain, NULL,
			   flags & NTLM_USE_UNICODE,
			   (u_char *) challenge, serverinlen);
    if (result != SASL_OK) goto cleanup;
    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "server domain: %s", domain);

    if (flags & NTLM_AUTH_NTLM) {
	params->utils->log(NULL, SASL_LOG_DEBUG,
			   "calculating NT response");
	P24(resp, P21(hash, password->data, P16_nt), challenge->nonce);
	nt_resp = resp;
    }
    else {
	params->utils->log(NULL, SASL_LOG_DEBUG,
			   "calculating LM response");
	P24(resp, P21(hash, password->data, P16_lm), challenge->nonce);
	lm_resp = resp;
    }

    /* we don't care about wkstn or session key */
    result = create_response(params->utils, text, lm_resp, nt_resp,
			     domain, oparams->authid,
			     NULL, NULL, flags, clientoutlen);
    if (result != SASL_OK) goto cleanup;

    *clientout = text->out_buf;

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;
    
    result = SASL_OK;

  cleanup:
    if (domain) params->utils->free(domain);
    if (free_password) _plug_free_secret(params->utils, &password);

    return result;
}

static int ntlm_client_mech_step(void *conn_context,
				sasl_client_params_t *params,
				const char *serverin,
				unsigned serverinlen,
				sasl_interact_t **prompt_need,
				const char **clientout,
				unsigned *clientoutlen,
				sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    *clientout = NULL;
    *clientoutlen = 0;
    
    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "NTLM client step %d\n", text->state);

    switch (text->state) {
	
    case 1:
	return ntlm_client_mech_step1(text, params, serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    case 2:
	return ntlm_client_mech_step2(text, params, serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    default:
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid NTLM client step %d\n", text->state);
	return SASL_FAIL;
    }
    
    return SASL_FAIL; /* should never get here */
}

static void ntlm_client_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);
    
    utils->free(text);
}

static sasl_client_plug_t ntlm_client_plugins[] = 
{
    {
	"NTLM",				/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&ntlm_client_mech_new,		/* mech_new */
	&ntlm_client_mech_step,		/* mech_step */
	&ntlm_client_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int ntlm_client_plug_init(sasl_utils_t *utils,
			 int maxversion,
			 int *out_version,
			 sasl_client_plug_t **pluglist,
			 int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = ntlm_client_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}
