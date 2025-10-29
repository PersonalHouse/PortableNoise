using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// The Curve25519 DH function (aka "X25519" in
    /// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
    /// </summary>
    public sealed class BCCurve25519 : Curve25519
    {
        public int DhLen => X25519.ScalarSize;

        public KeyPair GenerateKeyPair()
        {
            SecureRandom Random = new SecureRandom();
            IAsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            var pubkp = kp.Public as X25519PublicKeyParameters;
            var prikp = kp.Private as X25519PrivateKeyParameters;
            return new KeyPair(prikp.GetEncoded(), pubkp.GetEncoded());
        }

        public KeyPair GenerateKeyPair(ReadOnlySpan<byte> privateKey)
        {
            Debug.Assert(privateKey.Length == DhLen);

            var prikey = new X25519PrivateKeyParameters(privateKey.ToArray());
            return new KeyPair(prikey.GetEncoded(), prikey.GeneratePublicKey().GetEncoded());

        }

        public void Dh(KeyPair keyPair, ReadOnlySpan<byte> publicKey, Span<byte> sharedKey)
        {
            Debug.Assert(keyPair.PrivateKey != null && keyPair.PrivateKey.Length == DhLen);
            Debug.Assert(publicKey.Length == DhLen);
            Debug.Assert(sharedKey.Length == DhLen);



            var prikey = new X25519PrivateKeyParameters(keyPair.PrivateKey);
            var pubkey = new X25519PublicKeyParameters(publicKey.ToArray());
            X25519Agreement agreeA = new X25519Agreement();
            agreeA.Init(prikey);
            byte[] secretA = new byte[agreeA.AgreementSize];
            agreeA.CalculateAgreement(pubkey, secretA, 0);
            secretA.CopyTo(sharedKey);
        }
    }
}
