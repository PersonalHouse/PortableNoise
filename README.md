Portable.Noise is a fork of [Noise.Net](https://github.com/Metalnem/noise) with the following changes:


1. The max message size is a setting value now. Noise protocol has 64k limitation on the max message size and [Noise.Net](https://github.com/Metalnem/noise) implement it as a constant. The default setting value of Portable.Noise is 64k, which is compatible with Noise protocol.
2. Merge "Out of order" from [Zetanova](https://github.com/Zetanova/noise/tree/out-of-order-counter)
3. Add helper functions (GetEncryptedMessageSize,GetDecryptedMessageSize)



![](Noise.png)

[![Latest Version](https://img.shields.io/nuget/v/Noise.NET.svg)](https://www.nuget.org/packages/Noise.NET)
[![Build Status](https://travis-ci.org/Metalnem/noise.svg?branch=master)](https://travis-ci.org/Metalnem/noise)
[![Build status](https://ci.appveyor.com/api/projects/status/aw4y7rackgepjy8u?svg=true)](https://ci.appveyor.com/project/Metalnem/noise)
[![Docs](https://img.shields.io/badge/docs-API-orange.svg?style=flat)](https://metalnem.github.io/noise/api/Noise.html)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/noise/master/LICENSE)

.NET Standard 1.3 implementation of the [Noise Protocol Framework](https://noiseprotocol.org/)
(revision 33 of the [spec](https://noiseprotocol.org/noise.html)). It features:

- AESGCM and ChaChaPoly ciphers
- Curve25519 Diffie-Hellman function
- SHA256, SHA512, BLAKE2s, and BLAKE2b hash functions
- Support for multiple pre-shared symmetric keys
- All known [one-way] and [interactive] patterns from the specification
- XXfallback handshake pattern

[one-way]: https://noiseprotocol.org/noise.html#one-way-handshake-patterns
[interactive]: https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental

## Usage

1. Include the Noise namespace.

```csharp
using Noise;
```

2. Choose the handshake pattern and cryptographic functions.

```csharp
var protocol = new Protocol(
  HandshakePattern.IK,
  CipherFunction.ChaChaPoly,
  HashFunction.Blake2s,
  PatternModifiers.Psk2
);
```

3. Start the handshake by instantiating the protocol with the necessary parameters.

```csharp
// s is communicated out-of-band
// psk is a 32-byte pre-shared symmetric key

var initiator = protocol.Create(
  initiator: true,
  rs: rs,
  psks: new byte[][] { psk }
);

var responder = protocol.Create(
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

See [Noise.Examples](https://github.com/Metalnem/noise/tree/master/Noise.Examples)
for the complete example.

## Installation

```
> dotnet add package Noise.NET --version 1.0.0
```
