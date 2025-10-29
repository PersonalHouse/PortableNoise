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
    public class BCBlake2b : Blake2b
    {
        Blake2bDigest hash;

        public BCBlake2b()
        {
            hash = new Blake2bDigest();
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
