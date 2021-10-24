using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable InconsistentNaming

namespace DSA {
    public class DSA : IDisposable {
        private readonly SHA256                _sha256 = SHA256.Create();
        private readonly RandomNumberGenerator _rng    = RandomNumberGenerator.Create();

        private const int L  = 2048;
        private const int N  = 256;
        private const int NB = N / 8;

        private BigInteger Q;
        private BigInteger P;
        private BigInteger G;
        private BigInteger X;
        private BigInteger Y;

        private BigInteger H(byte[] input) {
            return new BigInteger(_sha256.ComputeHash(input), true);
        }

        public DSA() {
            GenerateKeys();
        }

        private void GenerateRandomPrimes() {
            using var dsa        = System.Security.Cryptography.DSA.Create(L);
            var       parameters = dsa.ExportParameters(true);
            P = new BigInteger(parameters.P, true, true);
            Q = new BigInteger(parameters.Q, true, true);
        }

        private void GenerateKeys() {
            GenerateRandomPrimes();
            BigInteger H = 2;
            G = H.ModPow((P - 1) / Q, P);

            X = _rng.NextBigInteger(1, Q);
            Y = G.ModPow(X, P);
        }

        public byte[] Sign(string message) {
            var messageBytes = Encoding.Default.GetBytes(message);
            return Sign(messageBytes);
        }

        public byte[] Sign(byte[] message) {
            var signature = new byte[NB * 2];

            repeat:
            try {
                var M = message;
                var K = _rng.NextBigInteger(1, Q);
                var R = G.ModPow(K, P) % Q;
                if (R == BigInteger.Zero)
                    goto repeat;

                var S = K.ModInverse(Q) * (H(M) + X * R) % Q;
                if (S == BigInteger.Zero)
                    goto repeat;

                WriteR(R, signature);
                WriteS(S, signature);
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
            var M = message;
            var R = GetR(signature);
            var S = GetS(signature);

            if (R == BigInteger.Zero || R >= Q || S == BigInteger.Zero || S >= Q) {
                return false;
            }

            try {
                var W  = S.ModInverse(Q);
                var U1 = H(M) * W % Q;
                var U2 = R * W % Q;
                var V  = G.ModPow(U1, P) * Y.ModPow(U2, P) % P % Q;
                if (V != R) {
                    return false;
                }
            } catch (ArithmeticException) {
                return false;
            }

            return true;
        }

        private static void WriteR(BigInteger R, Span<byte> signature) {
            var rBlock = signature[..NB];
            R.TryWriteBytes(rBlock, out _, true);
        }

        private static void WriteS(BigInteger S, Span<byte> signature) {
            var sBlock = signature[NB..];
            S.TryWriteBytes(sBlock, out _, true);
        }

        private static BigInteger GetR(ReadOnlySpan<byte> signature) {
            var R = signature[..NB];
            return new BigInteger(R, true);
        }

        private static BigInteger GetS(ReadOnlySpan<byte> signature) {
            var S = signature[NB..];
            return new BigInteger(S, true);
        }

        protected virtual void Dispose(bool disposing) {
            if (disposing) {
                _sha256.Dispose();
                _rng.Dispose();
            }
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
