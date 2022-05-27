// Based on BlakeSharp
// by Dominik Reichl <dominik.reichl@t-online.de>
// and BLAKE2 reference source code package C# implementation
// by Christian Winnerlein <codesinchaos@gmail.com>.

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PortableNoise.Engine.InProject
{
    /// <summary>
    /// BLAKE2s from <see href="https://tools.ietf.org/html/rfc7693">RFC 7693</see>
    /// with digest length 32.
    /// </summary>
    public sealed class InProjectBlake2s : Blake2s
    {
        private const uint IV0 = 0x6a09e667u;
		private const uint IV1 = 0xbb67ae85u;
		private const uint IV2 = 0x3c6ef372u;
		private const uint IV3 = 0xa54ff53au;
		private const uint IV4 = 0x510e527fu;
		private const uint IV5 = 0x9b05688cu;
		private const uint IV6 = 0x1f83d9abu;
		private const uint IV7 = 0x5be0cd19u;

		private const int OutputSize = 32;
		private const int BlockSize = 64;

		private const int FanOut = 1;
		private const int MaxHeight = 1;
		private const int Config = OutputSize | FanOut << 16 | MaxHeight << 24;

		private readonly uint[] h = new uint[OutputSize / 4];
		private readonly uint[] m = new uint[BlockSize / 4];

		private uint t0;
		private uint t1;
		private uint f;

		private readonly byte[] buffer = new byte[BlockSize];
		private int position;

		public InProjectBlake2s()
		{
			Reset();
		}

		public int HashLen => OutputSize;
		public int BlockLen => BlockSize;

		public void AppendData(ReadOnlyMemory<byte> data)
		{
			if (data.IsEmpty)
			{
				return;
			}

			var buffer = this.buffer.AsMemory();
			var left = BlockSize - position;

			if (position > 0 && data.Length > left)
			{
				data.Slice(0, left).CopyTo(buffer.Slice(position));

				t0 += BlockSize;
				t1 += t0 == 0 ? 1u : 0;

				Compress(buffer.Span);
				data = data.Slice(left);

				position = 0;
			}

			while (data.Length > BlockSize)
			{
				t0 += BlockSize;
				t1 += t0 == 0 ? 1u : 0;

				Compress(data.Slice(0, BlockSize).Span);
				data = data.Slice(BlockSize);
			}

			if (data.Length > 0)
			{
				data.CopyTo(buffer.Slice(position));
				position += data.Length;
			}
		}

		public void GetHashAndReset(Memory<byte> hash)
		{
			Debug.Assert(hash.Length == HashLen);

			t0 += (uint)position;
			f = uint.MaxValue;

			buffer.AsSpan(position).Fill(0);
			Compress(buffer);

			MemoryMarshal.AsBytes(h.AsSpan()).CopyTo(hash.Span);
			Reset();
		}

		private void Reset()
		{
			h[0] = IV0 ^ Config;
			h[1] = IV1;
			h[2] = IV2;
			h[3] = IV3;
			h[4] = IV4;
			h[5] = IV5;
			h[6] = IV6;
			h[7] = IV7;

			t0 = 0;
			t1 = 0;
			f = 0;

			Array.Clear(buffer, 0, buffer.Length);
			position = 0;
		}

		private void Compress(ReadOnlySpan<byte> block)
		{
			var h = this.h;
			var m = this.m;

			if (BitConverter.IsLittleEndian)
			{
				block.CopyTo(MemoryMarshal.AsBytes(m.AsSpan()));
			}
			else
			{
				for (int i = 0; i < 16; ++i)
				{
					m[i] = BinaryPrimitives.ReadUInt32BigEndian(block);
					block = block.Slice(4);
				}
			}

			var v0 = h[0];
			var v1 = h[1];
			var v2 = h[2];
			var v3 = h[3];
			var v4 = h[4];
			var v5 = h[5];
			var v6 = h[6];
			var v7 = h[7];

			var v8 = IV0;
			var v9 = IV1;
			var v10 = IV2;
			var v11 = IV3;
			var v12 = IV4 ^ t0;
			var v13 = IV5 ^ t1;
			var v14 = IV6 ^ f;
			var v15 = IV7;

			// G(0, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[0];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[1];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(0, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[2];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[3];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(0, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[4];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[5];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(0, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[6];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[7];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(0, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[8];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[9];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(0, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[10];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[11];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(0, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[12];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[13];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(0, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[14];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[15];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(1, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[14];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[10];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(1, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[4];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[8];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(1, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[9];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[15];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(1, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[13];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[6];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(1, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[1];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[12];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(1, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[0];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[2];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(1, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[11];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[7];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(1, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[5];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[3];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(2, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[11];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[8];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(2, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[12];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[0];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(2, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[5];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[2];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(2, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[15];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[13];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(2, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[10];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[14];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(2, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[3];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[6];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(2, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[7];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[1];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(2, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[9];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[4];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(3, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[7];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[9];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(3, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[3];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[1];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(3, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[13];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[12];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(3, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[11];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[14];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(3, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[2];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[6];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(3, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[5];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[10];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(3, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[4];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[0];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(3, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[15];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[8];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(4, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[9];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[0];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(4, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[5];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[7];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(4, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[2];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[4];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(4, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[10];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[15];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(4, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[14];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[1];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(4, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[11];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[12];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(4, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[6];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[8];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(4, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[3];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[13];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(5, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[2];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[12];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(5, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[6];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[10];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(5, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[0];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[11];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(5, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[8];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[3];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(5, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[4];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[13];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(5, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[7];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[5];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(5, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[15];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[14];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(5, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[1];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[9];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(6, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[12];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[5];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(6, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[1];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[15];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(6, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[14];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[13];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(6, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[4];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[10];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(6, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[0];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[7];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(6, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[6];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[3];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(6, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[9];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[2];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(6, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[8];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[11];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(7, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[13];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[11];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(7, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[7];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[14];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(7, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[12];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[1];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(7, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[3];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[9];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(7, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[5];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[0];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(7, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[15];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[4];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(7, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[8];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[6];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(7, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[2];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[10];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(8, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[6];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[15];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(8, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[14];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[9];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(8, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[11];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[3];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(8, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[0];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[8];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(8, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[12];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[2];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(8, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[13];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[7];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(8, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[1];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[4];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(8, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[10];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[5];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(9, 0, v0, v4, v8, v12)
			v0 = v0 + v4 + m[10];
			v12 ^= v0;
			v12 = (v12 >> 16) | (v12 << 16);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 12) | (v4 << 20);
			v0 = v0 + v4 + m[2];
			v12 ^= v0;
			v12 = (v12 >> 8) | (v12 << 24);
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = (v4 >> 7) | (v4 << 25);

			// G(9, 1, v1, v5, v9, v13)
			v1 = v1 + v5 + m[8];
			v13 ^= v1;
			v13 = (v13 >> 16) | (v13 << 16);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 12) | (v5 << 20);
			v1 = v1 + v5 + m[4];
			v13 ^= v1;
			v13 = (v13 >> 8) | (v13 << 24);
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(9, 2, v2, v6, v10, v14)
			v2 = v2 + v6 + m[7];
			v14 ^= v2;
			v14 = (v14 >> 16) | (v14 << 16);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 12) | (v6 << 20);
			v2 = v2 + v6 + m[6];
			v14 ^= v2;
			v14 = (v14 >> 8) | (v14 << 24);
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(9, 3, v3, v7, v11, v15)
			v3 = v3 + v7 + m[1];
			v15 ^= v3;
			v15 = (v15 >> 16) | (v15 << 16);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 12) | (v7 << 20);
			v3 = v3 + v7 + m[5];
			v15 ^= v3;
			v15 = (v15 >> 8) | (v15 << 24);
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(9, 4, v0, v5, v10, v15)
			v0 = v0 + v5 + m[15];
			v15 ^= v0;
			v15 = (v15 >> 16) | (v15 << 16);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 12) | (v5 << 20);
			v0 = v0 + v5 + m[11];
			v15 ^= v0;
			v15 = (v15 >> 8) | (v15 << 24);
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = (v5 >> 7) | (v5 << 25);

			// G(9, 5, v1, v6, v11, v12)
			v1 = v1 + v6 + m[9];
			v12 ^= v1;
			v12 = (v12 >> 16) | (v12 << 16);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 12) | (v6 << 20);
			v1 = v1 + v6 + m[14];
			v12 ^= v1;
			v12 = (v12 >> 8) | (v12 << 24);
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = (v6 >> 7) | (v6 << 25);

			// G(9, 6, v2, v7, v8, v13)
			v2 = v2 + v7 + m[3];
			v13 ^= v2;
			v13 = (v13 >> 16) | (v13 << 16);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 12) | (v7 << 20);
			v2 = v2 + v7 + m[12];
			v13 ^= v2;
			v13 = (v13 >> 8) | (v13 << 24);
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = (v7 >> 7) | (v7 << 25);

			// G(9, 7, v3, v4, v9, v14)
			v3 = v3 + v4 + m[13];
			v14 ^= v3;
			v14 = (v14 >> 16) | (v14 << 16);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 12) | (v4 << 20);
			v3 = v3 + v4 + m[0];
			v14 ^= v3;
			v14 = (v14 >> 8) | (v14 << 24);
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = (v4 >> 7) | (v4 << 25);

			h[0] ^= v0 ^ v8;
			h[1] ^= v1 ^ v9;
			h[2] ^= v2 ^ v10;
			h[3] ^= v3 ^ v11;
			h[4] ^= v4 ^ v12;
			h[5] ^= v5 ^ v13;
			h[6] ^= v6 ^ v14;
			h[7] ^= v7 ^ v15;
		}

		public void Dispose()
		{
		}
	}
}