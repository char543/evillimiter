import os
import ssl
import threading
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertAuthority(object):
    """
    A local certificate authority for on-the-fly TLS interception.

    Generates (once) a root CA, then mints a leaf certificate per requested
    host and hands back an ``ssl.SSLContext`` ready for the server side of a
    handshake. Leaf certs and contexts are cached. Clients that validate will
    only accept these unless the root CA is installed in their trust store
    (its path is exposed via :pyattr:`ca_cert_path`); clients that do not
    strictly validate accept them as-is.
    """

    def __init__(self, ca_dir=None):
        self.ca_dir = ca_dir or os.path.expanduser('~/.evillimiter/ca')
        self.ca_key_path = os.path.join(self.ca_dir, 'evillimiter-ca.key')
        self.ca_cert_path = os.path.join(self.ca_dir, 'evillimiter-ca.crt')
        self._leaf_dir = os.path.join(self.ca_dir, 'leaves')

        self._lock = threading.Lock()
        self._contexts = {}        # host -> ssl.SSLContext
        self._ca_key = None
        self._ca_cert = None
        self._load_or_create_ca()

    # --- CA ---------------------------------------------------------------
    def _load_or_create_ca(self):
        os.makedirs(self.ca_dir, exist_ok=True)
        os.makedirs(self._leaf_dir, exist_ok=True)

        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, 'rb') as f:
                self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, 'rb') as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'evillimiter Root CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'evillimiter'),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(self.ca_key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        os.chmod(self.ca_key_path, 0o600)
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self._ca_key, self._ca_cert = key, cert

    # --- leaf certs -------------------------------------------------------
    def _mint_leaf(self, host):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san = [x509.IPAddress(ipaddress.ip_address(host))]
        except ValueError:
            san = [x509.DNSName(host)]

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()), critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )

        safe = host.replace(':', '_').replace('/', '_').replace('*', '_')
        chain_path = os.path.join(self._leaf_dir, safe + '.pem')
        key_path = os.path.join(self._leaf_dir, safe + '.key')
        with open(chain_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))  # include CA so clients get the chain
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        return chain_path, key_path

    def context_for(self, host):
        """Return a cached server SSLContext presenting a leaf cert for *host*."""
        host = (host or 'unknown').lower()
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            chain_path, key_path = self._mint_leaf(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=chain_path, keyfile=key_path)
            self._contexts[host] = ctx
            return ctx
