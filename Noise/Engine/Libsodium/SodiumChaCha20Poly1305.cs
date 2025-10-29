using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using PortableNoise.Engine.Libsodium;

namespace PortableNoise.Engine.Libsodium
{
    /// <summary>
    /// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
    /// The 96-bit nonce is formed by encoding 32 bits
    /// of zeros followed by little-endian encoding of n.
    /// </summary>
    public sealed class SodiumChaCha20Poly1305 : Engine.ChaCha20Poly1305
    {

    public int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
		Debug.Assert(k.Length == Aead.KeySize);
		Debug.Assert(ciphertext.Length >= plaintext.Length + Aead.TagSize);

		Span<byte> nonce = stackalloc byte[Aead.NonceSize];
		BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4), n);

        int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
            ref MemoryMarshal.GetReference(ciphertext),
            out long length,
            ref MemoryMarshal.GetReference(plaintext)
            ,
			plaintext.Length,ad,ad?.Length??0,IntPtr.Zero,
			ref MemoryMarshal.GetReference(nonce),
			k);

		if (result != 0)
		{
			throw new CryptographicException("Encryption failed.");
		}

		Debug.Assert(length == plaintext.Length + Aead.TagSize);
		return (int)length;
	}

    public int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
		Debug.Assert(k.Length == Aead.KeySize);
		Debug.Assert(ciphertext.Length >= Aead.TagSize);
		Debug.Assert(plaintext.Length >= ciphertext.Length - Aead.TagSize);

		Span<byte> nonce = stackalloc byte[Aead.NonceSize];
		BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4), n);

        int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(
             ref MemoryMarshal.GetReference(plaintext), out long length, IntPtr.Zero,
            ref MemoryMarshal.GetReference(ciphertext)
            , ciphertext.Length,
            ad, ad?.Length??0, ref MemoryMarshal.GetReference(nonce), k
        );

		if (result != 0)
		{
			throw new CryptographicException("Decryption failed.");
		}

		Debug.Assert(length == ciphertext.Length - Aead.TagSize);
		return (int)length;
	}
    }
}
