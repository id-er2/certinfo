import contextlib
from datetime import datetime, timedelta, timezone
import io
import ipaddress
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
import certinfo as c

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def certificate(key=None, san=True):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.test')])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(42)
               .not_valid_before(NOW).not_valid_after(NOW + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('example.test'), x509.IPAddress(ipaddress.ip_address('192.0.2.1'))]), critical=False)
    return builder.sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = certificate()
        cls.pem = cls.cert.public_bytes(serialization.Encoding.PEM)
        cls.der = cls.cert.public_bytes(serialization.Encoding.DER)

    def check(self, data=None, now=NOW):
        return c.inspect_certificate(data or self.pem, now)

    def test_pem(self): self.assertEqual(self.check()['serial_hex'], '2A')
    def test_der(self): self.assertEqual(self.check(self.der)['serial_hex'], '2A')
    def test_fingerprint(self): self.assertEqual(self.check()['sha256'], self.cert.fingerprint(hashes.SHA256()).hex())
    def test_dates(self): self.assertEqual(self.check()['date_status'], 'within_dates')
    def test_before(self): self.assertEqual(self.check(now=NOW-timedelta(seconds=1))['date_status'], 'not_yet_valid')
    def test_after(self): self.assertEqual(self.check(now=NOW+timedelta(days=31))['date_status'], 'expired')
    def test_end_boundary(self): self.assertEqual(self.check(now=NOW+timedelta(days=30))['date_status'], 'within_dates')
    def test_naive(self):
        with self.assertRaises(c.CertificateError): self.check(now=NOW.replace(tzinfo=None))
    def test_san(self): self.assertEqual(len(self.check()['subject_alt_names']), 2)
    def test_no_san(self): self.assertEqual(self.check(certificate(san=False).public_bytes(serialization.Encoding.DER))['subject_alt_names'], [])
    def test_ec(self): self.assertEqual(self.check()['public_key']['curve'], 'secp256r1')
    def test_ca(self): self.assertFalse(self.check()['basic_constraints']['ca'])
    def test_ed25519(self): self.assertIsNone(self.check(certificate(ed25519.Ed25519PrivateKey.generate()).public_bytes(serialization.Encoding.DER))['signature_hash'])
    def test_garbage(self):
        for data in (b'', b'bad certificate', b'-----BEGIN PRIVATE KEY-----', b'x'*(c.MAX_BYTES+1)):
            with self.subTest(data=data[:20]), self.assertRaises(c.CertificateError): c.parse_certificate(data)
    def test_bundle(self):
        with self.assertRaises(c.CertificateError): c.parse_certificate(self.pem+self.pem)
    def test_trailing(self):
        for data in (self.pem+b'junk', b'junk'+self.pem, self.der+b'junk'):
            with self.assertRaises(c.CertificateError): c.parse_certificate(data)
    def test_private_key(self):
        key=ec.generate_private_key(ec.SECP256R1())
        private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        with self.assertRaises(c.CertificateError): c.parse_certificate(private)
    def test_cli(self):
        with tempfile.NamedTemporaryFile() as f, contextlib.redirect_stdout(io.StringIO()) as out:
            f.write(self.pem);f.flush()
            self.assertEqual(c.main([f.name,'--json']),0)
            self.assertIn('within_dates' if datetime.now(timezone.utc)<=NOW+timedelta(days=30) else 'expired',out.getvalue())
    def test_missing(self):
        with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(c.main(['/not/a/certificate']),2)
    def test_warning(self): self.assertIn('No chain',self.check()['note'])

if __name__ == '__main__': unittest.main()
