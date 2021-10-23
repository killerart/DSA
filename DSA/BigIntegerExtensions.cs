using System;
using System.Numerics;
using System.Security.Cryptography;

namespace DSA {
    public static class BigIntegerExtensions {
        public static BigInteger ModInverse(this BigInteger a, BigInteger m) {
            var (gcd, x, _) = GcdExtended(a, m);
            if (gcd != BigInteger.One) {
                throw new ArithmeticException("GCD should not be equal to 1");
            }

            return (x % m + m) % m;
        }

        public static (BigInteger gcd, BigInteger x, BigInteger y) GcdExtended(BigInteger a, BigInteger b) {
            if (a == BigInteger.Zero) {
                return (b, BigInteger.Zero, BigInteger.One);
            }

            var (gcd, x1, y1) = GcdExtended(b % a, a);
            var x = y1 - (b / a) * x1;
            var y = x1;
            return (gcd, x, y);
        }

        public static BigInteger ModPow(this BigInteger value, BigInteger exponent, BigInteger modulus) {
            return BigInteger.ModPow(value, exponent, modulus);
        }
    }

    public static class RandomBigInteger {
        public static BigInteger NextBigInteger(this RNGCryptoServiceProvider r, int bitLength) {
            if (bitLength < 1)
                return BigInteger.Zero;

            var bytes = bitLength / 8;
            var bits  = bitLength % 8;

            var bs = new byte[bytes + 1];
            r.GetBytes(bs);

            byte mask = (byte)(0xFF >> (8 - bits));
            bs[^1] &= mask;

            return new BigInteger(bs);
        }

        public static BigInteger NextBigInteger(this RNGCryptoServiceProvider r, BigInteger start, BigInteger end) {
            if (start == end)
                return start;

            var res = end;

            if (start > end) {
                end   = start;
                start = res;
                res   = end - start;
            } else
                res -= start;

            var bs = res.ToByteArray(true);

            var  bits = 8;
            byte mask = 0x7F;
            while ((bs[^1] & mask) == bs[^1]) {
                bits--;
                mask >>= 1;
            }

            bits += 8 * bs.Length;

            return r.NextBigInteger(bits + 1) * res / BigInteger.Pow(2, bits + 1) + start;
        }
    }
}
