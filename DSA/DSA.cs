using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable ClassWithVirtualMembersNeverInherited.Global
// ReSharper disable InconsistentNaming

namespace DSA {
    public class DSA : IDisposable {
        private readonly RandomNumberGenerator _rng    = RandomNumberGenerator.Create();
        private readonly SHA256                _sha256 = SHA256.Create();

        private const int L  = 2048;
        private const int N  = 256;
        private const int NB = N / 8;

        private BigInteger g;
        private BigInteger p;
        private BigInteger q;

        private BigInteger x;
        private BigInteger y;

        public DSA() {
            GenerateKeys();
        }

        private BigInteger H(byte[] input) {
            return new BigInteger(_sha256.ComputeHash(input), true);
        }

        private void GenerateRandomPrimes() {
            using var dsa        = System.Security.Cryptography.DSA.Create(L);
            var       parameters = dsa.ExportParameters(true);
            p = new BigInteger(parameters.P, true, true);
            q = new BigInteger(parameters.Q, true, true);
        }

        private void GenerateKeys() {
            GenerateRandomPrimes();
            BigInteger h = 2;
            g = h.ModPow((p - 1) / q, p);

            x = _rng.NextBigInteger(1, q);
            y = g.ModPow(x, p);
        }

        public byte[] Sign(string message) {
            var messageBytes = Encoding.Default.GetBytes(message);
            return Sign(messageBytes);
        }

        public byte[] Sign(byte[] message) {
            var signature = new byte[NB * 2];

            repeat:
            try {
                var m = message;
                var k = _rng.NextBigInteger(1, q);
                var r = g.ModPow(k, p) % q;
                if (r == BigInteger.Zero)
                    goto repeat;

                var s = k.ModInverse(q) * (H(m) + x * r) % q;
                if (s == BigInteger.Zero)
                    goto repeat;

                WriteR(r, signature);
                WriteS(s, signature);
            } catch (ArithmeticException) {
                goto repeat;
            }

            return signature;
        }

        public bool Verify(string message, ReadOnlySpan<byte> signature) {
            var messageBytes = Encoding.Default.GetBytes(message);
            return Verify(messageBytes, signature);
        }

        public bool Verify(byte[] message, ReadOnlySpan<byte> signature) {
            var m = message;
            var r = GetR(signature);
            var s = GetS(signature);

            if (r == BigInteger.Zero || s == BigInteger.Zero || r >= q || s >= q) {
                return false;
            }

            try {
                var w  = s.ModInverse(q);
                var u1 = H(m) * w % q;
                var u2 = r * w % q;
                var v  = g.ModPow(u1, p) * y.ModPow(u2, p) % p % q;
                if (v != r) {
                    return false;
                }
            } catch (ArithmeticException) {
                return false;
            }

            return true;
        }

        private static void WriteR(BigInteger r, Span<byte> signature) {
            var rBlock = signature[..NB];
            r.TryWriteBytes(rBlock, out _, true);
        }

        private static void WriteS(BigInteger s, Span<byte> signature) {
            var sBlock = signature[NB..];
            s.TryWriteBytes(sBlock, out _, true);
        }

        private static BigInteger GetR(ReadOnlySpan<byte> signature) {
            var r = signature[..NB];
            return new BigInteger(r, true);
        }

        private static BigInteger GetS(ReadOnlySpan<byte> signature) {
            var s = signature[NB..];
            return new BigInteger(s, true);
        }

        protected virtual void Dispose(bool disposing) {
            if (!disposing)
                return;
            _sha256.Dispose();
            _rng.Dispose();
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
