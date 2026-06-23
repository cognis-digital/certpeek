// certpeek — X.509 certificate auditor (C# / .NET)
// Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
//
// Usage:
//   certpeek <cert.pem|cert.crt|cert.der>   analyze a certificate file
//   certpeek -                              read PEM from stdin
//   certpeek --selftest                     generate a self-signed cert and analyze it (demo/CI)
//
// Output: a JSON object on stdout. Exit code 2 if any HIGH finding (expired / weak key).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

static class CertPeek
{
    static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            Console.Error.WriteLine("usage: certpeek <file.pem|.crt|.der> | - (stdin) | --selftest");
            return args.Length == 0 ? 1 : 0;
        }

        X509Certificate2 cert;
        try
        {
            cert = args[0] switch
            {
                "--selftest" => MakeSelfSigned(),
                "-"          => LoadPem(Console.In.ReadToEnd()),
                _            => LoadFile(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"certpeek: cannot parse certificate: {ex.Message}");
            return 1;
        }

        var findings = new List<Finding>();
        void Add(string sev, string id, string msg) => findings.Add(new Finding(sev, id, msg));

        var now = DateTime.UtcNow;
        int daysLeft = (int)Math.Floor((cert.NotAfter.ToUniversalTime() - now).TotalDays);

        if (now > cert.NotAfter.ToUniversalTime()) Add("HIGH", "expired", $"certificate expired {-daysLeft} day(s) ago");
        else if (daysLeft <= 30)                   Add("MEDIUM", "expiring", $"certificate expires in {daysLeft} day(s)");
        if (now < cert.NotBefore.ToUniversalTime()) Add("MEDIUM", "not-yet-valid", "notBefore is in the future");

        int keyBits = KeyBits(cert);
        string keyAlg = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown";
        if (keyAlg.Contains("RSA", StringComparison.OrdinalIgnoreCase) && keyBits > 0 && keyBits < 2048)
            Add("HIGH", "weak-key", $"RSA key is {keyBits} bits (< 2048)");

        string sig = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown";
        if (sig.Contains("sha1", StringComparison.OrdinalIgnoreCase) || sig.Contains("md5", StringComparison.OrdinalIgnoreCase))
            Add("HIGH", "weak-signature", $"weak signature algorithm: {sig}");

        if (string.Equals(cert.SubjectName.Name, cert.IssuerName.Name, StringComparison.Ordinal))
            Add("INFO", "self-signed", "subject equals issuer (self-signed)");

        var report = new Dictionary<string, object?>
        {
            ["tool"] = "certpeek",
            ["subject"] = cert.SubjectName.Name,
            ["issuer"] = cert.IssuerName.Name,
            ["serial"] = cert.SerialNumber,
            ["not_before"] = cert.NotBefore.ToUniversalTime().ToString("o"),
            ["not_after"] = cert.NotAfter.ToUniversalTime().ToString("o"),
            ["days_remaining"] = daysLeft,
            ["key_algorithm"] = keyAlg,
            ["key_bits"] = keyBits,
            ["signature_algorithm"] = sig,
            ["thumbprint_sha1"] = cert.Thumbprint,
            ["subject_alt_names"] = SubjectAltNames(cert),
            ["findings"] = findings,
        };

        Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        return findings.Any(f => f.severity == "HIGH") ? 2 : 0;
    }

    record Finding(string severity, string id, string message);

    static int KeyBits(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return rsa.KeySize;
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null) return ecdsa.KeySize;
        return 0;
    }

    static List<string> SubjectAltNames(X509Certificate2 cert)
    {
        var outp = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // subjectAltName
            {
                var s = new AsnEncodedData(ext.Oid, ext.RawData).Format(false);
                outp.AddRange(s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
        }
        return outp;
    }

    static X509Certificate2 LoadFile(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(bytes);
        if (text.Contains("-----BEGIN")) return LoadPem(text);
        return new X509Certificate2(bytes); // DER
    }

    static X509Certificate2 LoadPem(string pem) => X509Certificate2.CreateFromPem(pem);

    static X509Certificate2 MakeSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=certpeek.selftest.cognis.digital", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("selftest.cognis.digital");
        req.CertificateExtensions.Add(san.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
    }
}
