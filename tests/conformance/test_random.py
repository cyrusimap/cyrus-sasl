"""Random numbers for nonces, salts and challenges (sasl_rand).

SCRAM takes its nonces and salts from the library's sasl_rand(), and
sasl_mkchal() uses it for challenges.  RFC 5802 needs nonces that differ
for every authentication and randomly generated salts, and points to
RFC 4086 (BCP 106) for how to produce them: from a cryptographically
secure generator, so that no output can be predicted from earlier output.

These tests call the public sasl_rand API directly through ctypes.
"""

import ctypes
import glob
import os
import unittest

from sasltest import BUILDDIR, SANITIZED, spec

SAMPLE = 32  # octets drawn per pool; 256 bits never collide by chance


def load_libsasl():
    libdir = os.path.join(BUILDDIR, os.pardir, "lib", ".libs")
    for path in sorted(glob.glob(os.path.join(libdir, "libsasl2.so*"))
                       + glob.glob(os.path.join(libdir, "libsasl2*.dylib"))):
        try:
            lib = ctypes.CDLL(path)
        except OSError:
            continue
        lib.sasl_randcreate.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.sasl_randcreate.restype = ctypes.c_int
        lib.sasl_randfree.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.sasl_randfree.restype = None
        lib.sasl_randseed.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.c_uint]
        lib.sasl_randseed.restype = None
        lib.sasl_rand.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                  ctypes.c_uint]
        lib.sasl_rand.restype = None
        return lib
    return None


class RandomGenerator(unittest.TestCase):

    def setUp(self):
        if SANITIZED:
            # A sanitizer-built libsasl2 can't be loaded into an
            # uninstrumented Python process.
            self.skipTest("libsasl2 can't be loaded with ctypes in sanitizer builds")
        self.lib = load_libsasl()
        if self.lib is None:
            self.skipTest("built libsasl2 shared library not found")
        self.pools = []

    def tearDown(self):
        for pool in self.pools:
            self.lib.sasl_randfree(ctypes.byref(pool))

    def pool(self, seed=None):
        pool = ctypes.c_void_p()
        self.assertEqual(self.lib.sasl_randcreate(ctypes.byref(pool)), 0)
        self.pools.append(pool)
        if seed is not None:
            self.lib.sasl_randseed(pool, seed, len(seed))
        return pool

    def draw(self, pool, n=SAMPLE):
        buf = ctypes.create_string_buffer(n)
        self.lib.sasl_rand(pool, buf, n)
        return buf.raw

    @spec("RFC 5802", "5.1, 9", "SECURITY",
          "nonces and salts come from a cryptographically secure generator "
          "(RFC 4086), not one whose output follows from a small state")
    def test_output_not_determined_by_pool_state(self):
        # Two pools given the same state must still produce unrelated
        # output.  A generator whose output is a function of a 48-bit
        # state produces the same bytes from both.
        seed = b"\x01\x02\x03\x04\x05\x06"
        a = self.draw(self.pool(seed))
        b = self.draw(self.pool(seed))
        self.assertNotEqual(a, b)

    @spec("RFC 5802", "5.1, 9", "SECURITY",
          "nonces and salts come from a cryptographically secure generator "
          "(RFC 4086)")
    def test_unseeded_pools_differ(self):
        a = self.draw(self.pool())
        b = self.draw(self.pool())
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, bytes(SAMPLE))

    @spec("RFC 5802", "5.1", "SECURITY",
          "a long draw is filled completely, not just its first block")
    def test_long_draw_filled(self):
        # getrandom() and getentropy() can return less than asked for.
        n = 4096
        a = self.draw(self.pool(), n)
        self.assertEqual(len(a), n)
        self.assertNotEqual(a[-SAMPLE:], bytes(SAMPLE))
        self.assertGreater(len(set(a)), 200)


if __name__ == "__main__":
    unittest.main()
