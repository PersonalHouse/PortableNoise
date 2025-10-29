using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;

using Org.BouncyCastle.Crypto.Parameters;

using PortableNoise;

namespace BCvsSodium
{
    [SimpleJob(RuntimeMoniker.Net90)]
    [SimpleJob(RuntimeMoniker.NativeAot90)]
    public class TestNoisenet
    {
        List<byte[]> messages;
        public TestNoisenet()
        {
            int count = 1000000;
            messages = new List<byte[]>(count);
            for (int i = 0; i < count; i++)
            {
                var buf = new byte[1400];//16k
                for (int j = 0; j < buf.Length; j++)
                {
                    buf[j] = (byte)i;
                }
                messages.Add(buf);
            }
        }

        [Benchmark]
        public void Noisenet()
        {
            var protocol = new Noise.Protocol(
            Noise.HandshakePattern.IK,
            Noise.CipherFunction.ChaChaPoly,
            Noise.HashFunction.Blake2b,
            Noise.PatternModifiers.Psk2);


            // Generate static keys for the client and the server.
            using (var clientStatic = Noise.KeyPair.Generate())
            using (var serverStatic = Noise.KeyPair.Generate())
            {
                var psk = new byte[32];

                // Generate a random 32-byte pre-shared secret key.
                using (var random = RandomNumberGenerator.Create())
                {
                    random.GetBytes(psk);
                }
                using (var handshakeStatec = protocol.Create(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.Create(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[Noise.Protocol.MaxMessageLength];
                    var buffers = new byte[Noise.Protocol.MaxMessageLength];
                    var buffert = new byte[Noise.Protocol.MaxMessageLength];

                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            Memory<byte> request = message;

                            // Send the message to the server.
                            bytesWrittenc = transportc.WriteMessage(request.Span, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);

                            if (!request.Span.SequenceEqual(buffers.AsSpan(0, bytesReads)))
                            {
                                throw new Exception("failed");
                            }


                        }
                    }
                }
            }
        }



        [Benchmark]
        public void PortableNoiseLibsodium()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.Libsodium.SodiumChaCha20Poly1305,
            PortableNoise.Engine.Libsodium.SodiumCurve25519, PortableNoise.Engine.Libsodium.SodiumBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);

            var dh = new PortableNoise.Engine.Libsodium.SodiumCurve25519();
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
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffers = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffert = new byte[PortableNoise.Protocol.MaxMessageLength];


                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            byte[] request = message;

                            // Send the message to the server.

                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);

                            if (!request.AsSpan().SequenceEqual(buffers.AsSpan(0, bytesReads)))
                            {
                                throw new Exception("failed");
                            }
                        }
                    }
                }
            }
        }


        [Benchmark]
        public void PortableNoiseBouncyCastle()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve25519, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            var dh = new PortableNoise.Engine.BouncyCastle.BCCurve25519();
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
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffers = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffert = new byte[PortableNoise.Protocol.MaxMessageLength];


                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            byte[] request = message;

                            // Send the message to the server.

                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);

                            if (!request.AsSpan().SequenceEqual(buffers.AsSpan(0, bytesReads)))
                            {
                                throw new Exception("failed");
                            }
                        }
                    }
                }
            }
        }


        [Benchmark]
        public void PortableNoiseBouncyCastle448()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve448, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            var dh = new PortableNoise.Engine.BouncyCastle.BCCurve448();
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
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffers = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffert = new byte[PortableNoise.Protocol.MaxMessageLength];


                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            byte[] request = message;

                            // Send the message to the server.

                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);

                            if (!request.AsSpan().SequenceEqual(buffers.AsSpan(0, bytesReads)))
                            {
                                throw new Exception("failed");
                            }
                        }
                    }
                }
            }
        }



        [Benchmark]
        public void PortableNoiseBouncyCastle448MultipleSegBaseline()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve448, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            var dh = new PortableNoise.Engine.BouncyCastle.BCCurve448();
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
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffers = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffert = new byte[PortableNoise.Protocol.MaxMessageLength];


                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {

                        for (int i = 0; (i + 2) < messages.Count; i += 2)
                        {


                            byte[] request1 = messages[i];
                            byte[] request2 = messages[i + 1];
                            byte[] request = new byte[request1.Length + request2.Length];
                            System.Buffer.BlockCopy(request1, 0, request, 0, request1.Length);
                            System.Buffer.BlockCopy(request2, 0, request, request1.Length, request2.Length);

                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);

                            //                             if (!request.AsSpan().SequenceEqual(bufferc.AsSpan(0, bytesReadc)))
                            //                             {
                            //                                 throw new Exception("failed");
                            //                             }
                        }
                    }
                }
            }
        }



        [Benchmark]
        public void PortableNoiseBouncyCastle448MultipleSeg()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve448, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            var dh = new PortableNoise.Engine.BouncyCastle.BCCurve448();
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
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffers = new byte[PortableNoise.Protocol.MaxMessageLength];
                    var buffert = new byte[PortableNoise.Protocol.MaxMessageLength];


                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {

                        for (int i = 0; (i + 2) < messages.Count; i += 2)
                        {
                            byte[] request1 = messages[i];
                            byte[] request2 = messages[i + 1];

                            // Send the message to the server.
                            // Combine the two messages into one buffer
                            byte[] combinedRequest = new byte[request1.Length + request2.Length];
                            System.Buffer.BlockCopy(request1, 0, combinedRequest, 0, request1.Length);
                            System.Buffer.BlockCopy(request2, 0, combinedRequest, request1.Length, request2.Length);

                            bytesWrittenc = transportc.WriteMessage(combinedRequest, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);


                        }
                    }
                }
            }
        }

        //[Benchmark]
        public void TestBCChaCha20Poly1305()
        {

            Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();

            ulong n = 0;
            byte[] k = new byte[32];
            k[0] = 1;

            var buf = new byte[320000000];

            var nonce = new byte[12];
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            //var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce, null);


            cipher.Init(true, parameters);
            var t = 0;
            try
            {
                //Generate Cipher Text With Auth Tag       
                for (var i = 0; i < messages.Count; i++)
                {
                    byte[] request = messages[i];
                    var len = cipher.ProcessBytes(request, 0, request.Length, buf, t);
                    t += len;
                }
                t += cipher.DoFinal(buf, t);

            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new CryptographicException("Encrypt failed.");
            }


            cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce, null);
            var bufdes = new byte[320000000];
            cipher.Init(false, parameters);
            try
            {
                var len = cipher.ProcessBytes(buf, 0, t, bufdes, 0);
                var t2 = cipher.DoFinal(buf, len);

            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new CryptographicException("Encrypt failed.");
            }
        }

    }
}
