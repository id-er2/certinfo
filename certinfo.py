#!/usr/bin/env python3
"""Inspect one public X.509 certificate locally. Never supply private keys."""
import argparse
from datetime import datetime, timezone
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.exceptions import UnsupportedAlgorithm

MAX_BYTES = 1024 * 1024


class CertificateError(ValueError):
    pass


def parse_certificate(data):
    if not isinstance(data, bytes) or not data:
        raise CertificateError('Certificate must be nonempty bytes')
    if len(data) > MAX_BYTES:
        raise CertificateError('Certificate exceeds 1 MiB')
    if b'PRIVATE KEY' in data:
        raise CertificateError('Private keys are not accepted. Use a public certificate only')
    try:
        if b'-----BEGIN' in data:
            start = b'-----BEGIN CERTIFICATE-----'
            end = b'-----END CERTIFICATE-----'
            clean = data.strip()
            if clean.count(start) != 1 or clean.count(end) != 1 or not clean.startswith(start) or not clean.endswith(end):
                raise CertificateError('Provide exactly one PEM certificate, with no other blocks')
            return x509.load_pem_x509_certificate(clean)
        cert = x509.load_der_x509_certificate(data)
        if cert.public_bytes(serialization.Encoding.DER) != data:
            raise CertificateError('Trailing data or noncanonical DER is not accepted')
        return cert
    except (ValueError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, CertificateError):
            raise
        raise CertificateError('Could not parse a public PEM or DER X.509 certificate') from exc


def inspect_certificate(data, now=None):
    cert = parse_certificate(data)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise CertificateError('Comparison time must include a timezone')
    now = now.astimezone(timezone.utc)
    before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
    status = 'not_yet_valid' if now < before else 'expired' if now > after else 'within_dates'
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_info = {'type': 'RSA', 'bits': key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_info = {'type': 'EC', 'bits': key.key_size, 'curve': key.curve.name}
    elif isinstance(key, dsa.DSAPublicKey):
        key_info = {'type': 'DSA', 'bits': key.key_size}
    else:
        key_info = {'type': type(key).__name__}
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [{'type': type(n).__name__, 'value': str(n.value)} for n in san]
    except x509.ExtensionNotFound:
        names = []
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca = {'ca': constraints.ca, 'path_length': constraints.path_length}
    except x509.ExtensionNotFound:
        ca = None
    try:
        signature_hash = cert.signature_hash_algorithm
        signature_hash = signature_hash.name if signature_hash else None
    except UnsupportedAlgorithm:
        signature_hash = 'unsupported'
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_hex': format(cert.serial_number, 'X'),
        'version': cert.version.name,
        'not_before': before.isoformat(), 'not_after': after.isoformat(),
        'checked_at': now.isoformat(), 'date_status': status,
        'seconds_until_expiry': int((after - now).total_seconds()),
        'sha256': cert.fingerprint(hashes.SHA256()).hex(),
        'signature_oid': cert.signature_algorithm_oid.dotted_string,
        'signature_hash': signature_hash, 'public_key': key_info,
        'subject_alt_names': names, 'basic_constraints': ca,
        'note': 'Local metadata only. No chain, signature, hostname, revocation or trust validation. Matching issuer and subject does not prove a self-signature. within_dates is not a security verdict.'
    }


def read_certificate(path):
    with open(path, 'rb') as stream:
        return stream.read(MAX_BYTES + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('certificate', help='Path to one PUBLIC PEM or DER certificate, never a private key')
    parser.add_argument('--json', action='store_true', help='Print structured JSON')
    args = parser.parse_args(argv)
    try:
        result = inspect_certificate(read_certificate(args.certificate))
        if args.json:
            print(json.dumps(result, ensure_ascii=True, indent=2))
        else:
            for field in ('subject', 'issuer', 'serial_hex', 'not_before', 'not_after', 'date_status', 'sha256'):
                print(f'{field}: {result[field]}')
            print('public_key: ' + json.dumps(result['public_key']))
            print('subject_alt_names: ' + json.dumps(result['subject_alt_names'], ensure_ascii=True))
            print(result['note'])
        return 0
    except (OSError, CertificateError, ValueError, UnsupportedAlgorithm) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
