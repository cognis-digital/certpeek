# certpeek

**C# / .NET** — X.509 certificate auditor — expiry, weak keys, weak signatures, SANs.

[![ci](https://github.com/cognis-digital/certpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/certpeek/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C%23-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `certpeek` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "id": "1234567890",
  "name": "John Doe",
  "email": "johndoe@example.com",
  "certs": [
    {
      "serial_number": "ABC123",
      "subject": "/C=US/ST=State/L=Locality/O=Organization/CN=somehost.example",
      "issuer": "/C=US/ST=State/L=Locality/O=Organization/CN=someca.example",
      "not_before": 1643723400,
      "not_after": 1644325200
    },
    {
      "serial_number": "DEF456",
      "subject": "/C=US/ST=State/L=Locality/O=Organization/CN=somehost2.example",
      "issuer": "/C=US/ST=State/L=Locality/O=Organization/CN=someca.example",
      "not_before": 1644325200,
      "not_after": 1644927000
    }
  ]
}
```

<!-- cognis:example:end -->

## Build / run

```bash
dotnet build -c Release
dotnet run -- --selftest
```

## Usage

```
certpeek <cert.pem|.crt|.der>   analyze a certificate
certpeek -                       read PEM from stdin
certpeek --selftest              generate a self-signed cert and analyze it
```

## Output

A JSON object on stdout. Exit code **2** when findings exist, **0** when clean, **1** on error — so you can gate CI/pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
