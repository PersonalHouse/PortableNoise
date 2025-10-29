using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;

namespace PortableNoise
{
    /// <summary>
    /// abstract Protocol class
    /// </summary>
    public abstract class Protocol
    {
        /// <summary>
        /// Maximum size of the Noise protocol message in bytes.
        /// </summary>
        public static int MaxMessageLength = 65535;

        /// <summary>
        /// Preshared key size in bytes.
        /// </summary>
        public const int PSKSize = Aead.KeySize;

        /// <summary>
        /// Minimum size of the protocol name in bytes.
        /// </summary>
        protected static readonly int MinProtocolNameLength = "Noise_N_448_AESGCM_SHA256".Length;


        /// <summary>
        /// Maximum size of the protocol name in bytes.
        /// </summary>
        protected const int MaxProtocolNameLength = 255;
    }
    /// <summary>
    /// A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_SHA256 or Noise_IK_25519_ChaChaPoly_BLAKE2b).
    /// </summary>
    public sealed class Protocol<CipherType,DHType, HashType>: Protocol
        where CipherType : Cipher, new()
        where DHType : Dh, new()
        where HashType : Hash, new()
    {
        /// <summary>
        /// contructor
        /// </summary>
        /// <param name="handshakePattern"></param>
        /// <param name="modifiers"></param>
        public Protocol(HandshakePattern handshakePattern, PatternModifiers modifiers = PatternModifiers.None)
        {
            Exceptions.ThrowIfNull(handshakePattern, nameof(handshakePattern));

            HandshakePattern = handshakePattern;
            Modifiers = modifiers;

            Name = GetName();
        }



		private static readonly Dictionary<string, HandshakePattern> patterns = typeof(HandshakePattern).GetTypeInfo().DeclaredFields
			.Where(field => field.IsPublic && field.IsStatic && field.FieldType == typeof(HandshakePattern))
			.ToDictionary(field => field.Name, field => (HandshakePattern)field.GetValue(null));


		/// <summary>
		/// Gets the handshake pattern.
		/// </summary>
		public HandshakePattern HandshakePattern { get; }

		/// <summary>
		/// Gets the combination of pattern modifiers.
		/// </summary>
		public PatternModifiers Modifiers { get; }

		internal byte[] Name { get; }


        /// <summary>
        /// Creates an initial <see cref="HandshakeState&lt;CipherType, DhType, HashType>"/>.
        /// </summary>
        /// <param name="initiator">A boolean indicating the initiator or responder role.</param>
        /// <param name="prologue">
        /// A byte sequence which may be zero-length, or which may contain
        /// context information that both parties want to confirm is identical.
        /// </param>
        /// <param name="s">The local static private key (optional).</param>
        /// <param name="rs">The remote party's static public key (optional).</param>
        /// <param name="psks">The collection of zero or more 32-byte pre-shared secret keys.</param>
        /// <returns>The initial handshake state.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown if any of the following conditions is satisfied:
        /// <para>- <paramref name="s"/> is not a valid DH private key.</para>
        /// <para>- <paramref name="rs"/> is not a valid DH public key.</para>
        /// <para>- <see cref="HandshakePattern"/> requires the <see cref="HandshakeState&lt;CipherType, DhType, HashType>"/>
        /// to be initialized with local and/or remote static key,
        /// but <paramref name="s"/> and/or <paramref name="rs"/> is null.</para>
        /// <para>- One or more pre-shared keys are not 32 bytes in length.</para>
        /// <para>- Number of pre-shared keys does not match the number of PSK modifiers.</para>
        /// <para>- Fallback modifier is present (fallback can only be applied by calling
        /// the see Fallback method on existing handshake state).</para>
        /// </exception>
        public HandshakeState<CipherType, DHType, HashType> CreateHandshakeState(
            bool initiator,
            ReadOnlySpan<byte> prologue = default,
			byte[] s = default,
			byte[] rs = default,
			IEnumerable<byte[]> psks = default)
		{
			if (psks == null)
			{
				psks = Enumerable.Empty<byte[]>();
			}

            return new HandshakeState<CipherType, DHType, HashType>(this, initiator, prologue, s, rs, psks);

		}

        /// <summary>
        /// Creates an initial <see cref="HandshakeState&lt;CipherType, DhType, HashType>"/>.
        /// </summary>
        /// <param name="config">
        /// A set of parameters used to instantiate an
        /// initial <see cref="HandshakeState&lt;CipherType, DhType, HashType>"/>.
        /// </param>
        /// <returns>The initial handshake state.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the <paramref name="config"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any of the following conditions is satisfied:
        /// <para>- <paramref name="config"/> does not contain a valid DH private key.</para>
        /// <para>- <paramref name="config"/> does not contain a valid DH public key.</para>
        /// <para>- <see cref="HandshakePattern"/> requires the <see cref="HandshakeState&lt;CipherType, DhType, HashType>"/>
        /// to be initialized with local and/or remote static key,
        /// but <see cref="ProtocolConfig.LocalStatic"/> and/or
        /// <see cref="ProtocolConfig.RemoteStatic"/> is null.</para>
        /// <para>- One or more pre-shared keys are not 32 bytes in length.</para>
        /// <para>- Number of pre-shared keys does not match the number of PSK modifiers.</para>
        /// </exception>
        public HandshakeState<CipherType, DHType, HashType> CreateHandshakeState(ProtocolConfig config)
		{
			Exceptions.ThrowIfNull(config, nameof(config));

			return CreateHandshakeState(config.Initiator, config.Prologue, config.LocalStatic, config.RemoteStatic, config.PreSharedKeys);
		}

		private byte[] GetName()
		{
			var protocolName = new StringBuilder("Noise");

			protocolName.Append('_');
			protocolName.Append(HandshakePattern.Name);

			if (Modifiers != PatternModifiers.None)
			{
				var separator = string.Empty;

				foreach (PatternModifiers modifier in Enum.GetValues(typeof(PatternModifiers)))
				{
					if ((Modifiers & modifier) != PatternModifiers.None)
					{
						protocolName.Append(separator);
						protocolName.Append(modifier.ToString().ToLowerInvariant());
						separator = "+";
					}
				}
			}

            protocolName.Append('_');

            if (typeof(Engine.Curve25519).IsAssignableFrom(typeof(DHType)))
            {
                protocolName.Append("25519");
            }
            else if (typeof(Engine.Curve448).IsAssignableFrom(typeof(DHType)))
            {
                protocolName.Append("448");
            }
            else
            {
                throw new ArgumentException("Invalid CipherType");
            }

            protocolName.Append('_');            
            if (typeof(Engine.ChaCha20Poly1305).IsAssignableFrom(typeof(CipherType)))
            {
                protocolName.Append("ChaChaPoly");
            }
            else if (typeof(Engine.Aes256Gcm).IsAssignableFrom(typeof(CipherType))) 
            {
                protocolName.Append("AESGCM");
            }
            else
            {
                throw new ArgumentException("Invalid CipherType");
            }


			protocolName.Append('_');

            if (typeof(Engine.Sha256).IsAssignableFrom(typeof(HashType)))
            {
                protocolName.Append("SHA256");
            }
            else if (typeof(Engine.Sha512).IsAssignableFrom(typeof(HashType)))
            {
                protocolName.Append("SHA512");
            }
            else if (typeof(Engine.Blake2b).IsAssignableFrom(typeof(HashType)))
            {
                protocolName.Append("BLAKE2b");
            }
            else if (typeof(Engine.Blake2s).IsAssignableFrom(typeof(HashType)))
            {
                protocolName.Append("BLAKE2s");
            }
            else
            {
                throw new ArgumentException("Invalid CipherType");
            }

			Debug.Assert(protocolName.Length <= MaxProtocolNameLength);

			return Encoding.ASCII.GetBytes(protocolName.ToString());
		}

	}
}
