using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
    /// The 96-bit nonce is formed by encoding 32 bits
    /// of zeros followed by little-endian encoding of n.
    /// </summary>
    public sealed class BCChaCha20Poly1305 : ChaCha20Poly1305
    {
        public BCChaCha20Poly1305()
        {

        }

    public int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        Debug.Assert(k.Length == Aead.KeySize);
        Debug.Assert(ciphertext.Length >= plaintext.Length + Aead.TagSize);

        var nonce = new byte[Aead.NonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var associatedData = ad ?? Array.Empty<byte>();
        var parameters = new AeadParameters(new KeyParameter(k), Aead.TagSize * 8, nonce, associatedData);
        cipher.Init(true, parameters);

        try
        {
            var bytesProduced = cipher.ProcessBytes(plaintext, ciphertext);
            bytesProduced += cipher.DoFinal(ciphertext.Slice(bytesProduced));

            return bytesProduced;
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            throw new CryptographicException("Encrypt failed.");
        }
    }

    public int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Debug.Assert(k.Length == Aead.KeySize);
        Debug.Assert(ciphertext.Length >= Aead.TagSize);
        Debug.Assert(plaintext.Length >= ciphertext.Length - Aead.TagSize);

        var nonce = new byte[Aead.NonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var associatedData = ad ?? Array.Empty<byte>();
        var parameters = new AeadParameters(new KeyParameter(k), Aead.TagSize * 8, nonce, associatedData);
        cipher.Init(false, parameters);

        try
        {
            var bytesRead = cipher.ProcessBytes(ciphertext, plaintext);
            bytesRead += cipher.DoFinal(plaintext.Slice(bytesRead));

            return bytesRead;
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException )
        {
            throw new CryptographicException("Decryption failed.");
        }
    }	}
}
