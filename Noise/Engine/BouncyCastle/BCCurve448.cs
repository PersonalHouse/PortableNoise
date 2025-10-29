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
    /// The Curve448 DH function (aka "X448" in
    /// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
    /// </summary>
    public sealed class BCCurve448 : Curve448
    {
        public int DhLen => X448.ScalarSize;

        public KeyPair GenerateKeyPair()
        {
            SecureRandom Random = new SecureRandom();
            IAsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
            kpGen.Init(new X448KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            var pubkp = kp.Public as X448PublicKeyParameters;
            var prikp = kp.Private as X448PrivateKeyParameters;
            return new KeyPair(prikp.GetEncoded(), pubkp.GetEncoded());
        }

        public KeyPair GenerateKeyPair(ReadOnlySpan<byte> privateKey)
        {
            Debug.Assert(privateKey.Length == DhLen);

            var prikey = new X448PrivateKeyParameters(privateKey.ToArray());
            return new KeyPair(prikey.GetEncoded(), prikey.GeneratePublicKey().GetEncoded());

        }

        public void Dh(KeyPair keyPair, ReadOnlySpan<byte> publicKey, Span<byte> sharedKey)
        {
            Debug.Assert(keyPair.PrivateKey != null && keyPair.PrivateKey.Length == DhLen);
            Debug.Assert(publicKey.Length == DhLen);
            Debug.Assert(sharedKey.Length == DhLen);

            var prikey = new X448PrivateKeyParameters(keyPair.PrivateKey);
            var pubkey = new X448PublicKeyParameters(publicKey.ToArray());
            X448Agreement agreeA = new X448Agreement();
            agreeA.Init(prikey);
            byte[] secretA = new byte[agreeA.AgreementSize];
            agreeA.CalculateAgreement(pubkey, secretA, 0);
            secretA.CopyTo(sharedKey);
        }
    }
}
