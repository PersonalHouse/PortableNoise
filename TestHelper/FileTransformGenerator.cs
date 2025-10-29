using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace TestHelper
{


    [Generator]
    public class FileTransformGenerator : IIncrementalGenerator
    {
        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            // Get all additional text files
            var additionalTexts = context.AdditionalTextsProvider
                .Where(text => text.Path.Contains("Vectors") && text.Path.EndsWith(".txt"))
                .Collect();

            // Register source output
            context.RegisterSourceOutput(additionalTexts, (spc, texts) => Execute(spc, texts));
        }

        private void Execute(SourceProductionContext context, ImmutableArray<AdditionalText> additionalTexts)
        {
            if (additionalTexts.IsEmpty)
            {
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append($@"
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
{{
	public partial class NoiseTest
	{{

");

            bool ignoreNoisePSK = false;

            // Process cacophony.txt
            var cacophonyFile = additionalTexts.FirstOrDefault(t => t.Path.Contains("cacophony.txt") && !t.Path.Contains("\\c\\"));
            if (cacophonyFile != null)
            {
                var s = cacophonyFile.GetText(context.CancellationToken)?.ToString();
                if (s != null)
                {
                    GenerateTests(s, sb, "_cacophony", "CoreTest", ignoreNoisePSK);
                }
            }

            // Process snow-multipsk.txt
            var multipskFile = additionalTexts.FirstOrDefault(t => t.Path.Contains("snow-multipsk.txt"));
            if (multipskFile != null)
            {
                var s = multipskFile.GetText(context.CancellationToken)?.ToString();
                if (s != null)
                {
                    GenerateTests(s, sb, "_multipsk", "CoreTest", ignoreNoisePSK);
                }
            }

            // Process noise-c-fallback.txt
            var fallbackFile = additionalTexts.FirstOrDefault(t => t.Path.Contains("noise-c-fallback.txt"));
            if (fallbackFile != null)
            {
                var s = fallbackFile.GetText(context.CancellationToken)?.ToString();
                if (s != null)
                {
                    GenerateTests(s, sb, "_fb", "CoreTestFallback", ignoreNoisePSK);
                }
            }

            ignoreNoisePSK = true;

            // Process c/cacophony.txt
            var cCacophonyFile = additionalTexts.FirstOrDefault(t => t.Path.Contains("\\c\\") && t.Path.Contains("cacophony.txt"));
            if (cCacophonyFile != null)
            {
                var s = cCacophonyFile.GetText(context.CancellationToken)?.ToString();
                if (s != null)
                {
                    GenerateTests(s, sb, "_ncacophony", "CoreTest", ignoreNoisePSK);
                }
            }

            // Process c/noise-c-basic.txt
            var cBasicFile = additionalTexts.FirstOrDefault(t => t.Path.Contains("\\c\\") && t.Path.Contains("noise-c-basic.txt"));
            if (cBasicFile != null)
            {
                var s = cBasicFile.GetText(context.CancellationToken)?.ToString();
                if (s != null)
                {
                    GenerateTests(s, sb, "_ncb", "CoreTest", ignoreNoisePSK);
                }
            }

            sb.Append("/*");
            sb.Append("*/");

            sb.Append($@"

    }}
}}");
            context.AddSource("NoiseTest.Generated.cs", sb.ToString());
        }

        private void GenerateTests(string s, StringBuilder sb,string postfix,string testfunc, bool ignoreNoisePSK)
        {
            var json = JObject.Parse(s);
            if (true)
            {
                foreach (var vector in json["vectors"])
                {
                    var protocolName = GetString(vector, "protocol_name");

                    var protarr = protocolName.Split('_');

                    
                    if (ignoreNoisePSK && (protarr[0].StartsWith("noisepsk",true,System.Globalization.CultureInfo.InvariantCulture)))
                    {//noise-c has noisepsk protocol, which is incompatible with noise protocol
                        return;
                    }

                    var next = protarr[1];
                    var pattern = next.Length > 1 && char.IsUpper(next[1]) ? next.Substring(0, 2) : next.Substring(0, 1);
                    string fmodifiers = null;
                    var modifiers = next.Substring(pattern.Length).Split(new[] { '+' },StringSplitOptions.RemoveEmptyEntries);
                    foreach (var modifier in modifiers)
                    {
                        var m = modifier.Trim();
                        if (string.IsNullOrWhiteSpace(modifier))
                        {
                            m = "PatternModifiers.None";
                        }
                        else
                        {
                            m = m.Replace("psk", "Psk").Replace("fallback", "Fallback");
                            m = "PatternModifiers." + m;
                        }
                        if(string.IsNullOrWhiteSpace(fmodifiers))
                        {
                            fmodifiers = m;
                        }else
                        {
                            fmodifiers += $"|{m}";
                        }
                    }
                    if (string.IsNullOrWhiteSpace(fmodifiers))
                    {
                        fmodifiers = "PatternModifiers.None";
                    }
                    string ec = protarr[2];


                    string cipher = protarr[3];
                    if (string.Compare(cipher, "ChaChaPoly", true) == 0)
                    {
                        cipher = "ChaCha20Poly1305";
                    }
                    else if (string.Compare(cipher, "AESGCM", true) == 0)
                    {
                        cipher = "Aes256Gcm";
                    }
                    else
                    {
                        throw new Exception($"Get cipher {cipher} {protocolName}");
                    }


                    string hash = protarr[4];
                    string pre = "Engine.Libsodium.Sodium";
                    if (string.Compare(hash, "BLAKE2b", true) == 0)
                    {
                        hash = pre + "Blake2b";
                    }
                    else if (string.Compare(hash, "BLAKE2S", true) == 0)
                    {
                        hash = "Engine.InProject.InProjectBlake2s";
                    }
                    else if (string.Compare(hash, "Sha256", true) == 0)
                    {
                        hash = pre + "Sha256";
                    }
                    else if (string.Compare(hash, "Sha512", true) == 0)
                    {
                        hash = pre + "Sha512";
                    }
                    else
                    {
                        throw new Exception($"Get hash {hash} {protocolName}");
                    }


                    var scontent = vector.ToString();
                    scontent = scontent.Replace("\"", "\"\"");
                    if (ec != "448")
                    {

                        sb.Append($@"
    [Fact]
    private void Test{protocolName.Replace("+", "")}Sodium{postfix}()
    {{
        var s=@""{scontent}"";
        {testfunc}<{pre}{cipher},Engine.Libsodium.SodiumCurve{ec}, {hash}>(HandshakePattern.{pattern},{fmodifiers},s);

    }}
");
                    }
                    hash = protarr[4];
                    pre = "Engine.BouncyCastle.BC";
                    if (string.Compare(hash, "BLAKE2b", true) == 0)
                    {
                        hash = pre + "Blake2b";
                    }
                    else if (string.Compare(hash, "BLAKE2S", true) == 0)
                    {
                        hash = "Engine.InProject.InProjectBlake2s";
                    }
                    else if (string.Compare(hash, "Sha256", true) == 0)
                    {
                        hash = pre + "Sha256";
                    }
                    else if (string.Compare(hash, "Sha512", true) == 0)
                    {
                        hash = pre + "Sha512";
                    }
                    else
                    {
                        throw new Exception($"Get hash {hash} {protocolName}");
                    }
                    sb.Append($@"
    [Fact]
    private void Test{protocolName.Replace("+","")}BC{postfix}()
    {{

        var s=@""{scontent}"";
        {testfunc}<{pre}{cipher},Engine.BouncyCastle.BCCurve{ec}, {hash}>(HandshakePattern.{pattern},{fmodifiers},s);

    }}
");


                }
            }
        }

        private static string GetString(JToken token, string property)
        {
            return (string) token[property] ?? string.Empty;
        }
    }
}
