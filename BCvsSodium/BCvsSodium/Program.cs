using System;
using System.Buffers.Binary;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;

using Noise;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace BCvsSodium
{
    public class JitVsAotConfig : ManualConfig
    {
        public JitVsAotConfig()
        {
            // Add regular JIT job
            AddJob(Job.Default
                .WithId("JIT")
                .WithRuntime(CoreRuntime.Core90));

            // Add NativeAOT job
            AddJob(Job.Default
                .WithId("NativeAOT")
                .WithRuntime(NativeAotRuntime.Net90));
        }
    }

    [Config(typeof(JitVsAotConfig))]
    public class Program
    {
        byte[] data;
        byte[] Buffer;
        ulong n = 1;
        byte[] k = new byte[32];
        byte[] nonce = new byte[12];
        byte[] ad = new byte[32];
        byte[] tag = new byte[32];

        Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 bccipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 bccipher2 = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();

        System.Security.Cryptography.ChaCha20Poly1305 net6cipher;
        public Program()
        {
            data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 1, 2, 3, 4, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            Buffer = new byte[1024];
            if (System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
            {
                net6cipher = new System.Security.Cryptography.ChaCha20Poly1305(k);
            }
        }
        [Benchmark]
        public void BCChaCha20Poly1305Encrypt()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);
            var parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce);
            bccipher.Init(true, parameters);
            var len = bccipher.ProcessBytes(data, 0, data.Length, Buffer, 0);
            bccipher.DoFinal(Buffer, len);
        }

        [Benchmark]
        public void BCChaCha20Poly1305()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);
            var parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce);
            bccipher.Init(true, parameters);
            var len = bccipher.ProcessBytes(data, 0, data.Length, Buffer, 0);
            len += bccipher.DoFinal(Buffer, len);

            bccipher2.Init(false, parameters);
            var len2 = bccipher2.ProcessBytes(Buffer, 0, len, data, 0);
            bccipher2.DoFinal(Buffer, len2);
        }


        [Benchmark]
        public void BCAESGCMEncrypt()
        {
            GcmBlockCipher bcaescipher = new GcmBlockCipher(new AesEngine());

            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);
            var parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce);
            bcaescipher.Init(true, parameters);
            var len = bcaescipher.ProcessBytes(data, 0, data.Length, Buffer, 0);
            bcaescipher.DoFinal(Buffer, len);
        }


        [Benchmark]
        public void BCAESGCM()
        {
            GcmBlockCipher bcaescipher = new GcmBlockCipher(new AesEngine());
            GcmBlockCipher bcaescipher2 = new GcmBlockCipher(new AesEngine());

            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);
            var parameters = new AeadParameters(new KeyParameter(k), 16 * 8, nonce);
            bcaescipher.Init(true, parameters);
            var len = bcaescipher.ProcessBytes(data, 0, data.Length, Buffer, 0);
            len += bcaescipher.DoFinal(Buffer, len);

            bcaescipher2.Init(false, parameters);
            var len2 = bcaescipher2.ProcessBytes(Buffer, 0, len, data, 0);
            bcaescipher2.DoFinal(Buffer, len2);
        }

        [Benchmark]
        public void Net6ChaCha20Poly1305Encrypt()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            net6cipher.Encrypt(nonce, data, Buffer, tag, null);
        }

        [Benchmark]
        public void LibsodiumChaCha20Poly1305Encrypt()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
                ref Buffer[0],
                out long length,
                 ref data[0],
                data.Length,
                ref ad[0],
                0,
                IntPtr.Zero,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("Encryption failed.");
            }
        }


        [Benchmark]
        public void LibsodiumChaCha20Poly1305()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
                ref Buffer[0],
                out long length,
                 ref data[0],
                data.Length,
                ref ad[0],
                0,
                IntPtr.Zero,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("Encryption failed.");
            }


            result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                 ref data[0],
                out long length2,
                IntPtr.Zero,
                ref Buffer[0],
                length,
                ref ad[0],
                0,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("decryption failed.");
            }
        }


        [Benchmark]
        public void LibsodiumAESGCMEncrypt()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            int result = Libsodium.crypto_aead_aes256gcm_encrypt(
                ref Buffer[0],
                out long length,
                 ref data[0],
                data.Length,
                ref ad[0],
                0,
                IntPtr.Zero,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("Encryption failed.");
            }
        }

        [Benchmark]
        public void LibsodiumAESGCM()
        {
            ++n;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            int result = Libsodium.crypto_aead_aes256gcm_encrypt(
                ref Buffer[0],
                out long length,
                 ref data[0],
                data.Length,
                ref ad[0],
                0,
                IntPtr.Zero,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("Encryption failed.");
            }


            result = Libsodium.crypto_aead_aes256gcm_decrypt(
                 ref data[0],
                out long length2,
                IntPtr.Zero,
                ref Buffer[0],
                length,
                ref ad[0],
                0,
                ref nonce[0],
                ref k[0]
            );

            if (result != 0)
            {
                throw new Exception("decryption failed.");
            }
        }
        static void Main(string[] args)
        {
            //BenchmarkDotNet.Running.BenchmarkRunner.Run<Program>();
            BenchmarkDotNet.Running.BenchmarkRunner.Run<TestNoisenet>();
            return;

        }
    }
}
