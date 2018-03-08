using System;

namespace Noise
{
	/// <summary>
	/// A set of functions for instantiating a Noise protocol.
	/// </summary>
	public static class Protocol
	{
		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		public static IHandshakeState Create(
			CipherSuite cipherSuite,
			HandshakePattern handshakePattern,
			bool initiator,
			byte[] prologue,
			KeyPair s,
			byte[] rs)
		{

			if (cipherSuite.Cipher == CipherFunction.AesGcm && cipherSuite.Hash == HashFunction.Sha256)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha256>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipherSuite.Cipher == CipherFunction.AesGcm && cipherSuite.Hash == HashFunction.Sha512)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha512>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipherSuite.Cipher == CipherFunction.AesGcm && cipherSuite.Hash == HashFunction.Blake2b)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipherSuite.Cipher == CipherFunction.ChaChaPoly && cipherSuite.Hash == HashFunction.Sha256)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha256>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipherSuite.Cipher == CipherFunction.ChaChaPoly && cipherSuite.Hash == HashFunction.Sha512)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha512>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipherSuite.Cipher == CipherFunction.ChaChaPoly && cipherSuite.Hash == HashFunction.Blake2b)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Blake2b>(handshakePattern, initiator, prologue, s, rs);
			}
			else
			{
				throw new ArgumentException("Cipher suite not supported.", nameof(cipherSuite));
			}
		}

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		internal static bool Create(
			string protocolName,
			bool initiator,
			byte[] prologue,
			KeyPair s,
			byte[] rs,
			out IHandshakeState handshakeState)
		{
			if (protocolName == null)
			{
				throw new ArgumentNullException(nameof(protocolName));
			}

			handshakeState = null;

			if (protocolName.Length > Constants.MaxProtocolNameLength)
			{
				return false;
			}

			string[] parts = protocolName.Split('_');

			if (parts.Length != 5 || parts[0] != "Noise")
			{
				return false;
			}

			if (!HandshakePattern.TryGetValue(parts[1], out var pattern))
			{
				return false;
			}

			DhFunction dhType;
			CipherFunction cipherType;
			HashFunction hashType;

			switch (parts[2])
			{
				case "25519": dhType = DhFunction.Curve25519; break;
				default: return false;
			}

			switch (parts[3])
			{
				case "AESGCM": cipherType = CipherFunction.AesGcm; break;
				case "ChaChaPoly": cipherType = CipherFunction.ChaChaPoly; break;
				default: return false;
			}

			switch (parts[4])
			{
				case "SHA256": hashType = HashFunction.Sha256; break;
				case "SHA512": hashType = HashFunction.Sha512; break;
				case "BLAKE2b": hashType = HashFunction.Blake2b; break;
				default: return false;
			}

			CipherSuite cipherSuite = new CipherSuite(cipherType, dhType, hashType);
			handshakeState = Create(cipherSuite, pattern, initiator, prologue, s, rs);

			return true;
		}
	}
}
