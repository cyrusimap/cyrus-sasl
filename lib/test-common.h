/* -*- c++ -*- */
#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

/***************************************************************************
 *
 *           Copyright 1998 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * Carnegie Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.
 * 
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL Carnegie Mellon University BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * Author: Ryan Troll <ryan+@andrew.cmu.edu>
 * 
 * $Id: test-common.h,v 1.1 1998/11/19 02:00:26 ryan Exp $
 * 
 ***************************************************************************/

int test_WriteBuf(char prefix, int fd, char *buf, int buflen);
int test_ReadBuf(char prefix, int fd, char **buf, int *buflen);

int from64(char *out, char *in);
void to64(unsigned char *out, unsigned char *in, int inlen);

#endif /* _TEST_COMMON_H_ */
