"""Self-signed TLS certificate for the ballot server (pyca/cryptography).

Voters are given this exact certificate in their trust bundle and their
client trusts *only* it (certificate pinning), so an attacker in the middle
with any other certificate - even one signed by a public CA - is rejected.
"""

import datetime
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from evote.core.keystore import write_private_file


def generate_certificate(cert_path: str, key_path: str, passphrase: str,
                         hostnames: list[str], ip_addresses: list[str], days: int = 60) -> str:
    """Create an ECDSA P-256 key and a self-signed certificate. Returns the PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0] if hostnames else "evote-server"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "evote prototype")])
    alt_names = [x509.DNSName(h) for h in hostnames] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses]
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False, key_agreement=True,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, "wb") as fh:
        fh.write(pem)
    write_private_file(key_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))))
    return pem.decode("ascii")


def fingerprint(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
