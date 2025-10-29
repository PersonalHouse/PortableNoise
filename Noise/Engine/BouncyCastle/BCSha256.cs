using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using Org.BouncyCastle.Crypto.Digests;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// 
    /// </summary>
    public class BCSha256 : Sha256
    {
        Sha256Digest hash;

        public BCSha256()
        {
            hash = new Sha256Digest();
        }

        public int HashLen => 32;
        public int BlockLen => 64;

        public void AppendData(ReadOnlySpan<byte> data)
        {
            hash.BlockUpdate(data);
        }

        public void Dispose()
        {
        }

        public void GetHashAndReset(Span<byte> fhash)
        {
            hash.DoFinal(fhash);
            hash.Reset();
        }
    }
}
