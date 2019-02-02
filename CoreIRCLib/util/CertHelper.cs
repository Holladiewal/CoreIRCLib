using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Certificate = OpenSSL.X509.X509Certificate;
using X509Name = Org.BouncyCastle.Asn1.X509.X509Name;

namespace CoreIRCLib.util {
    public class CertHelper {
       public static X509Certificate2 genCert() {
           var gen = new X509V3CertificateGenerator();
           var keypairgen = new RsaKeyPairGenerator();
           keypairgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 4096));

           var keypair = keypairgen.GenerateKeyPair();
           var random = new Random();
           random.Next();random.Next();random.Next();random.Next();random.Next();random.Next();random.Next();

           var CN = new X509Name("CN=IRCLib");
           var SN = BigInteger.ProbablePrime(120, random);
           
           gen.SetSerialNumber(SN);
           gen.SetIssuerDN(CN);
           gen.SetSubjectDN(CN);
           gen.SetNotBefore(DateTime.UtcNow.Subtract(new TimeSpan(5, 0, 0)));
           gen.SetNotAfter(DateTime.UtcNow.AddYears(5));
           gen.SetPublicKey(keypair.Public);

           var gcert = gen.Generate(new Asn1SignatureFactory("MD5WithRSA", keypair.Private));
           Console.WriteLine($"Keypair results: Public: {keypair.Public}\nPrivate: {keypair.Private}");
           
           var cert = new X509Certificate2(gcert.GetEncoded(), "irclib", X509KeyStorageFlags.Exportable);
           
           Console.WriteLine($"Public Key: {cert.PublicKey}\nPrivate Key present: {cert.HasPrivateKey} at creation time.");
           
           return cert;
       }
            
        public static X509Certificate2 loadCert(string certpath, string password) {
            var cert = new X509Certificate2(certpath, password, X509KeyStorageFlags.Exportable);
            Console.WriteLine($"Public Key: {cert.PublicKey}\nPrivate Key present: {cert.HasPrivateKey}");
            return cert;
        }

        public static void saveCert(X509Certificate2 cert) {
            var bytes = cert.Export(X509ContentType.Pkcs12, "irclib");
            File.WriteAllBytes(@"IRCLib.pfx", bytes);
        }
    }
}