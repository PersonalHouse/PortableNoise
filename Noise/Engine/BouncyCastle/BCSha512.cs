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
    public class BCSha512 : Sha512
    {
        readonly Sha512Digest hash;

        public BCSha512()
        {
            hash = new Sha512Digest();
        }
        public int HashLen => 64;
        public int BlockLen => 128;

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
