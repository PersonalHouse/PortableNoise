# PortableNoise is a fork of [Noise.Net]

[Noise.Net]: https://github.com/Metalnem/noise



.NET Standard 2.0 implementation of the [Noise Protocol Framework](https://noiseprotocol.org/)
(revision 33 of the [spec](https://noiseprotocol.org/noise.html)). 

Noise.Net features:

- AESGCM and ChaChaPoly ciphers
- Curve25519 Diffie-Hellman function
- SHA256, SHA512, BLAKE2s, and BLAKE2b hash functions
- Support for multiple pre-shared symmetric keys
- All known [one-way] and [interactive] patterns from the specification
- XXfallback handshake pattern

[one-way]: https://noiseprotocol.org/noise.html#one-way-handshake-patterns
[interactive]: https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental

PortableNoise additional:
+ Multiple crypto libraries support. Currently supports Libsodium and BouncyCastle.
  - Libsodium performances better.

    |                           Method |       Mean |    Error |   StdDev |
    |--------------------------------- |-----------:|---------:|---------:|
    |        BCChaCha20Poly1305Encrypt |   923.9 ns |  3.13 ns |  2.93 ns |
    |               BCChaCha20Poly1305 | 2,143.0 ns |  5.65 ns |  5.29 ns |
    |                  BCAESGCMEncrypt | 2,052.8 ns |  9.32 ns |  8.72 ns |
    |                         BCAESGCM | 4,184.4 ns | 16.40 ns | 15.34 ns |
    | LibsodiumChaCha20Poly1305Encrypt |   376.4 ns |  0.36 ns |  0.32 ns |
    |        LibsodiumChaCha20Poly1305 |   766.6 ns |  0.97 ns |  0.86 ns |
    |           LibsodiumAESGCMEncrypt |   182.5 ns |  0.19 ns |  0.18 ns |
    |                  LibsodiumAESGCM |   354.6 ns |  1.20 ns |  1.12 ns |


  - BouncyCastle has more functionalities and interoperates better with Dotnet.

+ The X448 DH functions support.
+ Support IOS and Android if using BouncyCastle.
+ Refactoring:
  - The max message size is a setting now. There is 64k limitation on the max message size and [Noise.Net](https://github.com/Metalnem/noise) implement it as a constant. The default setting value of Portable.Noise is 64k, which is compatible with Noise protocol.
  - Merge "Out of order" from [Zetanova](https://github.com/Zetanova/noise/tree/out-of-order-counter)
  - Add helper functions (GetEncryptedMessageSize,GetDecryptedMessageSize)
  - [Noise.Net] supports parsing protocol name at runtime, but PortableNoise not. If crypto parameters are unknown at build time, Table lookup could be used to support this requirement.
  - Change input message type from ReadOnlySpan to ReadOnlySequence.
  - The following is the benchmark of 10K of 16KB messages.

| Method                                          | Mean    | Error    | StdDev   |
|------------------------------------------------ |--------:|---------:|---------:|
| Noisenet                                        | 3.129 s | 0.0033 s | 0.0027 s |
| PortableNoiseLibsodium                          | 3.004 s | 0.0056 s | 0.0053 s |
| PortableNoiseBouncyCastle                       | 5.282 s | 0.0475 s | 0.0371 s |
| PortableNoiseBouncyCastle448                    | 5.241 s | 0.0474 s | 0.0444 s |
| PortableNoiseBouncyCastle448MultipleSegBaseline | 4.702 s | 0.0671 s | 0.0560 s |
| PortableNoiseBouncyCastle448MultipleSeg         | 4.689 s | 0.0651 s | 0.0577 s |



Todo:

- [Noise.Net] keeps private key and psk in memory. We'll replace with call back functions.



## Usage

1. Include the Noise namespace.

```csharp
using PortableNoise;
```

2. Choose the handshake pattern and cryptographic functions.

```csharp
var protocol = new Protocol<Engine.Libsodium.SodiumChaCha20Poly1305,
            Engine.Libsodium.SodiumCurve25519,Engine.Libsodium.SodiumBlake2b>(
			HandshakePattern.IK,PatternModifiers.Psk2);
```

3. Start the handshake by instantiating the protocol with the necessary parameters.

```csharp
// s is communicated out-of-band
// psk is a 32-byte pre-shared symmetric key

var initiator = protocol.CreateHandshakeState(
  initiator: true,
  rs: rs,
  psks: new byte[][] { psk }
);

var responder = protocol.CreateHandshakeState(
  initiator: false,
  s: s,
  psks: new byte[][] { psk }
);
```

4. Send and receive messages.

```csharp
(written, hash, transport) = state.WriteMessage(message, outputBuffer);
(read, hash, transport) = state.ReadMessage(received, inputBuffer);

written = transport.WriteMessage(message, outputBuffer);
read = transport.ReadMessage(received, inputBuffer);
```

See [Noise.Examples](https://github.com/PersonalHouse/PortableNoise/tree/master/Noise.Examples)
for the complete example.

## Installation
Compile source code and publish.

```
> dotnet add package PortableNoise --version 1.2.0
```
