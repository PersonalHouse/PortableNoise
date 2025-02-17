﻿using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace PortableNoise.Examples
{
	public class Program
	{
		private static readonly Channel clientToServer = new Channel();
		private static readonly Channel serverToClient = new Channel();

		// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b
		private static readonly Protocol<Engine.Libsodium.SodiumChaCha20Poly1305,
            Engine.Libsodium.SodiumCurve25519, Engine.Libsodium.SodiumBlake2b> protocol = new Protocol<Engine.Libsodium.SodiumChaCha20Poly1305,
            Engine.Libsodium.SodiumCurve25519,Engine.Libsodium.SodiumBlake2b>(
			HandshakePattern.IK,
			PatternModifiers.Psk2
		);

		private static readonly List<string> messages = new List<string>
		{
			"Now that the party is jumping",
			"With the bass kicked in, the fingers are pumpin'",
			"Quick to the point, to the point no faking",
			"I'm cooking MC's like a pound of bacon"
		};

		public static void Main(string[] args)
		{
            var dh = new Engine.Libsodium.SodiumCurve25519();
            // Generate static keys for the client and the server.
            using (var clientStatic = dh.GenerateKeyPair())
			using (var serverStatic = dh.GenerateKeyPair())
			{
				var psk = new byte[32];

				// Generate a random 32-byte pre-shared secret key.
				using (var random = RandomNumberGenerator.Create())
				{
					random.GetBytes(psk);
				}

				// Initialize and run the client.
				var client = Task.Run(() => Client(clientStatic.PrivateKey, serverStatic.PublicKey, Singleton(psk)));

				// Initialize and run the server.
				var server = Task.Run(() => Server(serverStatic.PrivateKey, Singleton(psk)));

				client.GetAwaiter().GetResult();
			}
		}

		private static async Task Client(byte[] s, byte[] rs, IEnumerable<byte[]> psks)
		{
			var buffer = new byte[Protocol.MaxMessageLength];

			using (var handshakeState = protocol.CreateHandshakeState(true, s: s, rs: rs, psks: psks))
			{
				// Send the first handshake message to the server.
				var (bytesWritten, _, _) = handshakeState.WriteMessage(null, buffer);
				await clientToServer.Send(Slice(buffer, bytesWritten));

				// Receive the second handshake message from the server.
				var received = await serverToClient.Receive();
                var lis =new List<ArraySegment<byte>>();
                lis.Add(received);
                var (_, _, transport) = handshakeState.ReadMessage(lis, buffer);

				// Handshake complete, switch to transport mode.
				using (transport)
				{
					foreach (var message in messages)
					{
						var request = Encoding.UTF8.GetBytes(message);

                        // Send the message to the server.
                        lis.Clear();
                        lis.Add(request);
                        bytesWritten = transport.WriteMessage(lis, buffer);
						await clientToServer.Send(Slice(buffer, bytesWritten));

						// Receive the response and print it to the standard output.
						var response = await serverToClient.Receive();
                        lis.Clear();
                        lis.Add(response);
                        var bytesRead = transport.ReadMessage(lis, buffer);

						Console.WriteLine(Encoding.UTF8.GetString(Slice(buffer, bytesRead)));
					}
				}
			}
		}

		private static async Task Server(byte[] s, IEnumerable<byte[]> psks)
		{
			var buffer = new byte[Protocol.MaxMessageLength];

			using (var handshakeState = protocol.CreateHandshakeState(false, s: s, psks: psks))
			{
				// Receive the first handshake message from the client.
				var received = await clientToServer.Receive();
                var lis = new List<ArraySegment<byte>>();
                lis.Add(received);
                handshakeState.ReadMessage(lis, buffer);

				// Send the second handshake message to the client.
				var (bytesWritten, _, transport) = handshakeState.WriteMessage(null, buffer);
				await serverToClient.Send(Slice(buffer, bytesWritten));

				// Handshake complete, switch to transport mode.
				using (transport)
				{
					for (; ; )
					{
						// Receive the message from the client.
						var request = await clientToServer.Receive();
                        lis.Clear();
                        lis.Add(request);
                        var bytesRead = transport.ReadMessage(lis, buffer);

                        // Echo the message back to the client.
                        lis.Clear();
                        lis.Add(Slice(buffer, bytesRead));
                        bytesWritten = transport.WriteMessage(lis, buffer);
						await serverToClient.Send(Slice(buffer, bytesWritten));
					}
				}
			}
		}

		private static IEnumerable<T> Singleton<T>(T item)
		{
			yield return item;
		}

		private static byte[] Slice(byte[] array, int length)
		{
			return array.AsSpan(0, length).ToArray();
		}

		// Chanel simulates the network between the client and the server.
		private class Channel
		{
			private readonly BufferBlock<byte[]> buffer = new BufferBlock<byte[]>();

			public async Task Send(byte[] message)
			{
				await buffer.SendAsync(message);
			}

			public async Task<byte[]> Receive()
			{
				return await buffer.ReceiveAsync();
			}
		}
	}
}
