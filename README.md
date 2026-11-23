# certinfo

Inspect one public X.509 certificate from a local PEM or DER file. Prints its subject, issuer, dates, SHA-256 fingerprint, public-key details, subject alternative names and basic constraints.

**Never supply a private key, PKCS#12/PFX bundle, login credential or secret.** This tool is for public certificates only. It rejects PEM private-key blocks and certificate bundles, but rejection is not a secret-sanitizing service. Do not send private material to a bot to see whether it will reject it.

## Install

Python 3.10 or newer:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate with `.venv\Scripts\activate` instead. The only dependency is the `cryptography` package.

## Use

```sh
python certinfo.py certificate.pem
python certinfo.py certificate.der --json
python -m unittest -v
```

The input must contain exactly one public X.509 certificate, not a chain or a key. Maximum file size is 1 MiB. The command reads at most that limit plus one byte and does not modify the input. Use an ordinary certificate file, not a named pipe or device.

The JSON output includes:

- `subject`, `issuer`, `serial_hex` and X.509 `version`.
- `not_before`, `not_after` and `checked_at`, all UTC timestamps.
- `date_status`: `not_yet_valid`, `within_dates` or `expired`, based only on the local clock. The boundary timestamps are included in the date window.
- `seconds_until_expiry`: may be negative after expiry.
- `sha256`: fingerprint of the certificate's DER bytes, not of the PEM text file.
- `signature_oid` and `signature_hash`, plus public-key type, bit size and curve where available.
- `subject_alt_names` with each entry's type and value, and `basic_constraints` when present.

Exit code 0 means the file was parsed, even if its dates have expired. Exit code 2 means invalid input, a read failure or a parsing error. Output is data from the certificate, not trusted instructions. JSON escapes control characters; terminals can still display unusual subject text.

## What it checks, and what it does not

All inspection is local. There are no network requests, uploads, telemetry, remote certificate fetches or file writes in the tool. Installing dependencies may contact the package index. The CLI prints its result to standard output; your terminal, shell redirection or any wrapper may retain that output.

This is a metadata reader, **not a certificate validator**. It does not verify the certificate signature or chain, trusted roots, hostname, revocation (OCSP/CRL), certificate transparency, key usage or policy compliance. `within_dates` does not mean safe or trusted. Equal issuer and subject names do not prove the certificate is self-signed. A fingerprint is useful only when compared through a trusted independent source. A wrong local clock produces wrong date results.

Only one certificate is accepted so a chain is not silently reduced to its first entry. Extra PEM blocks, surrounding text, oversized files and trailing DER data are rejected. No private-key operation is offered.

If integrated into Telegram later, the uploaded public certificate and returned metadata pass through Telegram. That is different from running this local CLI. Never upload a private key, even to your own private bot.

## Tests

```sh
python -m unittest -v
```

The tests generate disposable test certificates in memory. They cover PEM/DER, fingerprints, date boundaries, future/expired certificates, SANs, key types, private-key rejection, bundles, trailing data, size limits and CLI errors. No real private key or live network is used by the tests.

## License

MIT. Copyright (c) 2026 Mahmood Abdulqhar Mohamad.
