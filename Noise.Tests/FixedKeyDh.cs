using System;

using PortableNoise.Engine;

namespace PortableNoise.Tests
{
	internal class FixedKeyDh<DhType> : Dh
                where DhType : Dh, new()
    {
		private static readonly DhType dh = new DhType();
		private readonly byte[] privateKey;

		public FixedKeyDh()
		{
		} 

		public FixedKeyDh(byte[] privateKey)
		{
			this.privateKey = privateKey;
		}

		public int DhLen => dh.DhLen;

		public KeyPair GenerateKeyPair()
		{
            return dh.GenerateKeyPair(privateKey);
		}

		public KeyPair GenerateKeyPair(ReadOnlySpan<byte> privateKey)
		{
			return dh.GenerateKeyPair(privateKey);
		}

		public void Dh(KeyPair keyPair, ReadOnlySpan<byte> publicKey, Span<byte> sharedKey)
		{
			dh.Dh(keyPair, publicKey, sharedKey);
		}
	}
}
