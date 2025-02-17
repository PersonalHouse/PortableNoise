using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using TestAllianceCommunicator;

using Xunit;

namespace PortableNoise.Tests
{
    public partial class NoiseTest
    {
        private static byte[] initBuffer = new byte[Protocol.MaxMessageLength];
        private static byte[] respBuffer = new byte[Protocol.MaxMessageLength];

        private void CoreTest<CipherType, DHType, HashType>(HandshakePattern handshake, PatternModifiers pattern, string content)
                where CipherType : Cipher, new()
                where DHType : Dh, new()
                where HashType : Hash, new()
        {
            var vector = JObject.Parse(content);

            var protocolName = GetString(vector, "protocol_name");

            var protarr = protocolName.Split('_');
            bool issinglepsk = false;
            if (string.Compare(protarr[0], "noisepsk", true) == 0)
            {
                issinglepsk = true;
            }

            var initPrologue = GetBytes(vector, "init_prologue");
            var initPsks = GetPsks(vector, "init_psks");
            var initStatic = GetBytes(vector, "init_static");
            var initEphemeral = GetBytes(vector, "init_ephemeral");
            var initRemoteStatic = GetBytes(vector, "init_remote_static");
            var respPrologue = GetBytes(vector, "resp_prologue");
            var respPsks = GetPsks(vector, "resp_psks");
            var respStatic = GetBytes(vector, "resp_static");
            var respEphemeral = GetBytes(vector, "resp_ephemeral");
            var respRemoteStatic = GetBytes(vector, "resp_remote_static");
            var handshakeHash = GetBytes(vector, "handshake_hash");

            Protocol<CipherType, DHType, HashType> protocol;
            if (issinglepsk)
            {
                var initPsk = GetBytes(vector, "init_psk");
                var respPsk = GetBytes(vector, "resp_psk");
                initPsks = new List<byte[]> { initPsk };
                respPsks = new List<byte[]> { respPsk };

                protocol = new Protocol<CipherType, DHType, HashType>(handshake, pattern|PatternModifiers.Psk2);
            }else
            {
                protocol = new Protocol<CipherType, DHType, HashType>(handshake, pattern);
            }


            var init = protocol.CreateHandshakeState(true, initPrologue, initStatic, initRemoteStatic, initPsks);
            var resp = protocol.CreateHandshakeState(false, respPrologue, respStatic, respRemoteStatic, respPsks);

            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var setDh = init.GetType().GetMethod("SetDh", flags);

            setDh.Invoke(init, new object[] { new FixedKeyDh<DHType>(initEphemeral) });
            setDh.Invoke(resp, new object[] { new FixedKeyDh<DHType>(respEphemeral) });

            Transport initTransport = null;
            Transport respTransport = null;

            byte[] initHandshakeHash = null;
            byte[] respHandshakeHash = null;

            foreach (var message in vector["messages"])
            {
                var payload =GetSeq(GetBytes(message, "payload"));
                var ciphertext = GetBytes(message, "ciphertext");

                List<ArraySegment<byte>> initMessage;
                Span<byte> respMessage = null;

                int initMessageSize;
                int respMessageSize;


                if (initTransport == null && respTransport == null)
                {
                    (initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                    (respMessageSize, respHandshakeHash, respTransport) = resp.ReadMessage(initMessage, respBuffer);
                    respMessage = respBuffer.AsSpan(0, respMessageSize);

                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));
                }
                else
                {
                    initMessageSize = initTransport.WriteMessage(payload, initBuffer);
                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                    respMessageSize = respTransport.ReadMessage(initMessage, respBuffer);
                    respMessage = respBuffer.AsSpan(0, respMessageSize);
                }

                Assert.Equal(ciphertext, initMessage.MergeToSpan().ToArray());
                Assert.Equal(payload.MergeToSpan().ToArray(), respMessage.ToArray());

                Swap(ref initBuffer, ref respBuffer);
                Swap(ref init, ref resp);

                if (initTransport != null && !initTransport.IsOneWay)
                {
                    Swap(ref initTransport, ref respTransport);
                }
            }

            if (handshakeHash.Length > 0)
            {
                Assert.Equal(handshakeHash, initHandshakeHash);
                Assert.Equal(handshakeHash, respHandshakeHash);
            }

            init.Dispose();
            resp.Dispose();

            initTransport.Dispose();
            respTransport.Dispose();
        }

        private List<ArraySegment<byte>> GetSeq(byte[] vs)
        {

            var lis = new List<ArraySegment<byte>>();

            var sn = Random.Shared.Next(0,vs.Length+1);
            if ((sn==0)|| (sn == vs.Length))
            {
                lis.Add(vs);
                return lis;
            }
            lis.Add(new ArraySegment<byte>(vs, 0, sn));
            lis.Add(new ArraySegment<byte>(vs, sn, vs.Length-sn));
            return lis;
        }

        private void CoreTestFallback<CipherType, DHType, HashType>(HandshakePattern handshake, PatternModifiers pattern, string content)
                where CipherType : Cipher, new()
                where DHType : Dh, new()
                where HashType : Hash, new()
        {

            var vector = JObject.Parse(content);
            var protocolName = GetString(vector, "protocol_name");

            if (protocolName.Contains("PSK"))
            {
                return;
            }


            var initPrologue = GetBytes(vector, "init_prologue");
            var initStatic = GetBytes(vector, "init_static");
            var initEphemeral = GetBytes(vector, "init_ephemeral");
            var initRemoteStatic = GetBytes(vector, "init_remote_static");
            var respPrologue = GetBytes(vector, "resp_prologue");
            var respStatic = GetBytes(vector, "resp_static");
            var respEphemeral = GetBytes(vector, "resp_ephemeral");
            var respRemoteStatic = GetBytes(vector, "resp_remote_static");
            var handshakeHash = GetBytes(vector, "handshake_hash");


            var fallbackProtocol = new Protocol<CipherType, DHType, HashType>(handshake, pattern);
            var initialProtocol = new Protocol<CipherType, DHType, HashType>(HandshakePattern.IK);

            var init = initialProtocol.CreateHandshakeState(true, initPrologue, initStatic, initRemoteStatic);
            var resp = initialProtocol.CreateHandshakeState(false, respPrologue, respStatic, respRemoteStatic);

            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var setDh = init.GetType().GetMethod("SetDh", flags);

            setDh.Invoke(init, new object[] { new FixedKeyDh<DHType>(initEphemeral) });
            setDh.Invoke(resp, new object[] { new FixedKeyDh<DHType>(respEphemeral) });

            Transport initTransport = null;
            Transport respTransport = null;

            byte[] initHandshakeHash = null;
            byte[] respHandshakeHash = null;

            bool fallback = false;

            foreach (var message in vector["messages"])
            {
                var payload = GetSeq(GetBytes(message, "payload"));
                var ciphertext = GetBytes(message, "ciphertext");

                List<ArraySegment<byte>> initMessage;
                List<ArraySegment<byte>> respMessage = default;

                int initMessageSize;
                int respMessageSize;

                if (!fallback)
                {
                    (initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                    try
                    {
                        resp.ReadMessage(initMessage, respBuffer);
                    }
                    catch (CryptographicException)
                    {

                        initMessage = new List<ArraySegment<byte>>();
                        initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                        var initConfig = new ProtocolConfig { Prologue = initPrologue, LocalStatic = initStatic };
                        init.Fallback(fallbackProtocol, initConfig);

                        var respConfig = new ProtocolConfig { Prologue = respPrologue, LocalStatic = respStatic };
                        resp.Fallback(fallbackProtocol, respConfig);

                        respMessage = payload;
                        fallback = true;
                    }
                }
                else if (initTransport == null && respTransport == null)
                {
                    (initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                    (respMessageSize, respHandshakeHash, respTransport) = resp.ReadMessage(initMessage, respBuffer);
                    respMessage = new List<ArraySegment<byte>>();
                    respMessage.Add(respBuffer.AsArraySegment(0, respMessageSize));


                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                }
                else
                {
                    initMessageSize = initTransport.WriteMessage(payload, initBuffer);
                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));

                    respMessageSize = respTransport.ReadMessage(initMessage, respBuffer);
                    respMessage = new List<ArraySegment<byte>>();
                    respMessage.Add(respBuffer.AsArraySegment(0, respMessageSize));

                    initMessage = new List<ArraySegment<byte>>();
                    initMessage.Add(initBuffer.AsArraySegment(0, initMessageSize));
                }

                Assert.Equal(ciphertext, initMessage.MergeToSpan().ToArray());
                Assert.Equal(payload.MergeToSpan().ToArray(), respMessage.MergeToSpan().ToArray());

                Swap(ref initBuffer, ref respBuffer);
                Swap(ref init, ref resp);
                Swap(ref initTransport, ref respTransport);
            }

            Assert.Equal(handshakeHash, initHandshakeHash);
            Assert.Equal(handshakeHash, respHandshakeHash);

            init.Dispose();
            resp.Dispose();

            initTransport.Dispose();
            respTransport.Dispose();
        }

        [Fact]
        public void TestOutOfOrder()
        {
            byte[] buffer1 = new byte[4098];
            byte[] buffer2 = new byte[4098];

            byte[] psk;
            using (var rnd = RandomNumberGenerator.Create())
                psk = new byte[32];


            var dh = new Engine.Libsodium.SodiumCurve25519();

            var initiator_static = dh.GenerateKeyPair();
            var responder_static = dh.GenerateKeyPair();

            //var protocol = Protocol.Parse("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b".AsSpan());

        // Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b
            Protocol<Engine.Libsodium.SodiumChaCha20Poly1305,
            Engine.Libsodium.SodiumCurve25519, Engine.Libsodium.SodiumBlake2b> protocol = new Protocol<Engine.Libsodium.SodiumChaCha20Poly1305,
            Engine.Libsodium.SodiumCurve25519, Engine.Libsodium.SodiumBlake2b>(
            HandshakePattern.IK,
            PatternModifiers.Psk2);

        var identifier = Encoding.UTF8.GetBytes("out-of-order test");

            var initiator = protocol.CreateHandshakeState(true, identifier,
                initiator_static.PrivateKey, responder_static.PublicKey, new[] { psk });

            var responder = protocol.CreateHandshakeState(false, identifier,
                responder_static.PrivateKey, null, new[] { psk });

            int bytesWritten, bytesRead;
            Transport initiator_transport;
            Transport responder_transport;

            //handshake
            (bytesWritten, _, _) = initiator.WriteMessage(null, buffer1);
            Assert.True(bytesWritten > 0);

            var lis = new List<ArraySegment<byte>>();
            lis.Add(new ArraySegment<byte>(buffer1, 0, bytesWritten));
            (bytesRead, _, _) = responder.ReadMessage(lis, Memory<byte>.Empty);
            Assert.True(bytesRead == 0);


            (bytesWritten, _, responder_transport) = responder.WriteMessage(null, buffer1);
            Assert.True(bytesWritten > 0);
            Assert.NotNull(responder_transport);

            lis.Clear();
            lis.Add(new ArraySegment<byte>(buffer1, 0, bytesWritten));
            (bytesRead, _, initiator_transport) = initiator.ReadMessage(lis, Memory<byte>.Empty);
            Assert.True(bytesRead == 0);
            Assert.NotNull(initiator_transport);

            //test: exchange single empty message from initiator to responder and back
            //wireguard: The responder must wait to use the new session until it has recieved one encrypted session packet from the initiator, in order to provide key confirmation. 
            ulong counter;

            bytesWritten = initiator_transport.WriteMessage(null, buffer1, out counter);
            Assert.Equal(0, (int) counter);
            Assert.True(bytesWritten == 16);

            lis.Clear();
            lis.Add(new ArraySegment<byte>(buffer1, 0, bytesWritten));
            bytesRead = responder_transport.ReadMessage(counter, lis, buffer2);
            Assert.Equal(0, bytesRead);

            bytesWritten = responder_transport.WriteMessage(null, buffer1, out counter);
            Assert.Equal(0, (int) counter);
            Assert.True(bytesWritten == 16);


            lis.Clear();
            lis.Add(new ArraySegment<byte>(buffer1, 0, bytesWritten));
            bytesRead = initiator_transport.ReadMessage(counter, lis, buffer2);
            Assert.Equal(0, bytesRead);


            //out-of-order messages
            var messages = new List<byte[]>();

            for (int i = 0; i < 5; i++)
            {
                lis.Clear();
                lis.Add(new ArraySegment<byte>(Encoding.UTF8.GetBytes($"Hallo {i}")));
                bytesWritten = initiator_transport.WriteMessage(lis, buffer1, out counter);
                Assert.Equal(i + 1, (int) counter);

                var byf = new byte[bytesWritten];
                Buffer.BlockCopy(buffer1, 0, byf, 0, bytesWritten);
                messages.Add(byf);
            }

            lis.Clear();
            lis.Add(messages[0]);
            bytesWritten = responder_transport.ReadMessage(1,lis, buffer2);
            Assert.Equal(7, bytesWritten);
            Assert.Equal("Hallo 0", Encoding.UTF8.GetString(buffer2.AsSpan().Slice(0, bytesWritten).ToArray()));

            for (int i = messages.Count - 2; i > 0; i--)
            {
                lis.Clear();
                lis.Add(messages[i]);
                bytesWritten = responder_transport.ReadMessage((ulong) i + 1, lis, buffer2);
                Assert.Equal(7, bytesWritten);
                Assert.Equal($"Hallo {i}", Encoding.UTF8.GetString(buffer2.AsSpan().Slice(0, bytesWritten).ToArray()));
            }

            lis.Clear();
            lis.Add(messages[4]);
            bytesWritten = responder_transport.ReadMessage(5, lis, buffer2);
            Assert.Equal(7, bytesWritten);
            Assert.Equal("Hallo 4", Encoding.UTF8.GetString(buffer2.AsSpan().Slice(0, bytesWritten).ToArray()));

            initiator.Dispose();
            responder.Dispose();

            initiator_transport.Dispose();
            responder_transport.Dispose();
        }

        private static string GetString(JToken token, string property)
        {
            return (string) token[property] ?? string.Empty;
        }

        private static byte[] GetBytes(JToken token, string property)
        {
            return Hex.Decode(GetString(token, property));
        }
//         private static IList<Memory<byte>> GetBytes2(JToken token, string property)
//         {
//             return new IList<Memory<byte>>(Hex.Decode(GetString(token, property)));
//         }

        private static List<byte[]> GetPsks(JToken token, string property)
        {
            return token[property]?.Select(psk => Hex.Decode((string) psk)).ToList();
        }

        private static void Swap<T>(ref T x, ref T y)
        {
            var temp = x;
            x = y;
            y = temp;
        }
    }
}
