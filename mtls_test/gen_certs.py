"""Generate a test PKI for exercising sn-proxy's mTLS features.

Produces, in this directory:

  ca.crt / ca.key            root CA
  dest.crt / dest.key        certificate for the mTLS destination server
  listener.crt / listener.key  certificate for the sn-proxy HTTPS listener
  client.crt / client.key    client identity (used both as the proxy's
                             upstream client cert and as a test client)
  client.p12                 PKCS#12 client identity   (password: testpass)
  server.p12                 PKCS#12 listener keystore (password: testpass)
  truststore.p12             PKCS#12 truststore — CA only (password: testpass)

PKCS#12 files use PBES2 (HMAC-SHA256 / AES-256-CBC), which is what
sn-proxy's `p12-keystore` dependency reads.

The truststore is written as a key entry whose certificate chain holds the
CA. p12-keystore surfaces a bare certificate only when it carries the Java
"trusted certificate" attribute (as `keytool -importcert` sets); a CA carried
inside a key entry's chain is read on every PKCS#12 toolchain, so the test
stays toolchain-independent.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent
PASSWORD = b"testpass"
NOW = datetime.datetime.now(datetime.timezone.utc)
SAN = x509.SubjectAlternativeName(
    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca():
    key = _keypair()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("sn-proxy test CA"))
        .issuer_name(_name("sn-proxy test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(cn, ca_key, ca_cert, server=False, client=False):
    key = _keypair()
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(SAN, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
    )
    eku = []
    if server:
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def write_pem(stem, key=None, cert=None):
    if key is not None:
        (OUT / f"{stem}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    if cert is not None:
        (OUT / f"{stem}.crt").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def p12_encryption():
    return (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(PASSWORD)
    )


def main():
    ca_key, ca_cert = make_ca()
    write_pem("ca", ca_key, ca_cert)

    dest_key, dest_cert = make_leaf("localhost", ca_key, ca_cert, server=True)
    write_pem("dest", dest_key, dest_cert)

    listener_key, listener_cert = make_leaf("localhost", ca_key, ca_cert, server=True)
    write_pem("listener", listener_key, listener_cert)

    client_key, client_cert = make_leaf("sn-proxy test client", ca_key, ca_cert, client=True)
    write_pem("client", client_key, client_cert)

    enc = p12_encryption()
    (OUT / "client.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"client", client_key, client_cert, [ca_cert], enc
        )
    )
    (OUT / "server.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"listener", listener_key, listener_cert, [ca_cert], enc
        )
    )
    (OUT / "truststore.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(b"ca", ca_key, ca_cert, [], enc)
    )

    print("generated test PKI in", OUT)
    for f in sorted(OUT.glob("*")):
        if f.suffix in (".crt", ".key", ".p12"):
            print(f"  {f.name}")


if __name__ == "__main__":
    main()
