using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;

using PortableNoise.Engine;
using PortableNoise.Engine.Libsodium;

using Xunit;

namespace PortableNoise.Tests
{
	public class BlakeTest
	{
		[Theory]
        [InlineData(CrytoEngineType.Libsodium)]
        [InlineData(CrytoEngineType.BouncyCastle)]
        public void TestVectors(CrytoEngineType para)
		{
			var s = File.ReadAllText("Vectors/blake2-kat.json");
			var json = JArray.Parse(s);

			using (var hasher = CrytoEngine.CreateBlake2s(para))
			{
				byte[] hash = new byte[hasher.HashLen];

				foreach (var vector in json)
				{
					var name = (string)vector["hash"];
					var input = Hex.Decode((string)vector["in"]);
					var key = (string)vector["key"];
					var output = Hex.Decode((string)vector["out"]);

					if (name == "blake2s" && string.IsNullOrEmpty(key))
					{
						hasher.AppendData(input);
						hasher.GetHashAndReset(hash);

						Assert.Equal(output, hash);
					}
				}
			}
		}


        [Theory]
        [InlineData(CrytoEngineType.Libsodium)]
        [InlineData(CrytoEngineType.BouncyCastle)]
        public void TestLargeInput(CrytoEngineType para)
        {
			var factor = 1031;
			var data = new byte[factor];

			using (var hasher = CrytoEngine.CreateBlake2s(para))
            {
				int count = 4 * factor * factor;

				for (int i = 0; i < count; ++i)
				{
					hasher.AppendData(data);
				}

				var hash = new byte[hasher.HashLen];
				hasher.GetHashAndReset(hash);

				string expected = "3c965aaac533c5a1715a40ae8beaf8d1fe1242502f2c30db34239b16c54b1d78";
				string actual = Hex.Encode(hash);

				Assert.Equal(expected, actual);
			}
		}

        [Theory]
        [InlineData(CrytoEngineType.Libsodium)]
        [InlineData(CrytoEngineType.BouncyCastle)]
        public void TestSplits(CrytoEngineType para)
        {
			var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray().AsSpan();

			using (var hasher = CrytoEngine.CreateBlake2s(para))
			{
				var hash1 = new byte[hasher.HashLen];
				var hash2 = new byte[hasher.HashLen];

				for (int i = 0; i <= data.Length; ++i)
				{
					hasher.AppendData(data.Slice(0, i));
					hasher.GetHashAndReset(hash1);

					for (int j = 0; j <= i; ++j)
					{
						for (int k = j; k <= i; ++k)
						{
							hasher.AppendData(data.Slice(0, j));
							hasher.AppendData(data.Slice(j, k - j));
							hasher.AppendData(data.Slice(k, i - k));
							hasher.GetHashAndReset(hash2);

							Assert.Equal(hash1, hash2);
						}
					}
				}
			}
		}
	}
}
