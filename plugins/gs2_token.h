/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GS2_TOKEN_H_
#define _GS2_TOKEN_H_ 1

#define g_OID_equal(o1, o2)                                             \
        (((o1)->length == (o2)->length) &&                              \
        (memcmp((o1)->elements, (o2)->elements, (o1)->length) == 0))

extern OM_uint32
gs2_verify_token_header(OM_uint32 *minor,
                        gss_const_OID mech,
                        size_t *body_size,
                        unsigned char **buf_in,
                        size_t toksize_in);

extern void
gs2_make_token_header(
    const gss_OID_desc *mech,
    size_t body_size,
    unsigned char **buf);

extern size_t
gs2_token_size(const gss_OID_desc *mech, size_t body_size);

#endif /* _GS2_TOKEN_H_ */
