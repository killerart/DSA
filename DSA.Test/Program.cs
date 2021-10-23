using System;

namespace DSA.Test {
    class Program {
        static void Main(string[] args) {
            var dsa = new DSA();

            Console.Write("Input message: ");
            var message = Console.ReadLine();

            var signature = dsa.Sign(message!);
            Console.WriteLine($"\nSignature: {Convert.ToHexString(signature)}\n");

            var valid = dsa.Verify(message, signature);
            Console.WriteLine($"Valid: {valid}");
        }
    }
}
