"""Make the self-signed HTTPS certificate for LAN mode (run once on the SERVER laptop).

    python -m backend.tls_cert --name netcommand-server
    python -m backend.tls_cert --name netcommand-server --name LAPTOP1 --out-dir C:\\netcommand-tls

Writes two files (default folder: backend/tls/, which Git ignores):
    server.crt  the certificate: PUBLIC. Copy it to each client laptop; the client trusts
                only this certificate (NETCOMMAND_API_CA_FILE), which pins it.
    server.key  the private key: SECRET. It stays on the server laptop only. Never copy it,
                never commit it, never put it in a client package.

The certificate is valid for the names given with --name (plus "localhost" and 127.0.0.1,
so the server laptop's own desktop can connect too). Clients connect by NAME, not by IP
address: when the phone hotspot gives the server a new IP address, only the name ->
address mapping changes on the clients (NETCOMMAND_API_ADDRESS or the hosts file); the
certificate and the pin stay the same. See docs/LAN_DEPLOYMENT.md.

Nothing secret is printed: only the file names and the certificate's SHA-256
fingerprint (public; compare it on both laptops to be sure the right file was copied).
"""
import argparse
import datetime
import ipaddress
import os
import re
import sys
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent / 'tls'
CERT_NAME, KEY_NAME = 'server.crt', 'server.key'
DEFAULT_DAYS = 825                       # about 27 months
_NAME = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                   r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')


class CertError(ValueError):
    """A problem with the arguments; the message is safe to show."""


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def check_names(names):
    out = []
    for name in names:
        name = (name or '').strip().lower()
        if _is_ip(name):
            raise CertError(f'"{name}" is an IP address; use --ip for addresses (names are '
                            f'recommended, because the hotspot can change the address).')
        if not _NAME.match(name):
            raise CertError(f'"{name}" is not a valid host name (letters, numbers, dashes, dots).')
        if name not in out:
            out.append(name)
    if not out:
        raise CertError('Give at least one host name with --name (for example netcommand-server).')
    return out


def build(names, ips=(), days=DEFAULT_DAYS):
    """(certificate PEM bytes, private key PEM bytes) for a self-signed server
    certificate (ECDSA P-256, SHA-256, serverAuth, not a CA)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    names = check_names(names)
    dns = names + (['localhost'] if 'localhost' not in names else [])
    addresses = [ipaddress.ip_address('127.0.0.1')]
    for ip in ips or ():
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise CertError(f'"{ip}" is not an IP address.') from None
        if address not in addresses:
            addresses.append(address)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'NetCommand (self-signed)')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=int(days)))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in dns] + [x509.IPAddress(a) for a in addresses]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def fingerprint(cert_pem):
    """SHA-256 fingerprint of a PEM certificate, as AA:BB:... (public information)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    digest = x509.load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA256())
    return ':'.join(f'{b:02X}' for b in digest)


def write(out_dir, names, ips=(), days=DEFAULT_DAYS, force=False):
    """Write server.crt and server.key into out_dir; (cert path, key path, fingerprint).
    Refuses to replace an existing key unless force (clients would need the new pin)."""
    folder = Path(out_dir)
    cert_path, key_path = folder / CERT_NAME, folder / KEY_NAME
    if (cert_path.exists() or key_path.exists()) and not force:
        raise CertError(f'{CERT_NAME} or {KEY_NAME} already exists in that folder. Use --force '
                        f'to replace them (every client must then get the new {CERT_NAME}).')
    cert_pem, key_pem = build(names, ips, days)
    folder.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_BINARY', 0)
    fd = os.open(key_path, flags, 0o600)                 # owner-only where the OS supports it
    with os.fdopen(fd, 'wb') as f:
        f.write(key_pem)
    cert_path.write_bytes(cert_pem)
    return cert_path, key_path, fingerprint(cert_pem)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m backend.tls_cert',
        description='Make the self-signed HTTPS certificate for NetCommand LAN mode.')
    parser.add_argument('--name', action='append', default=[], required=True,
                        help='host name clients will use (repeat for more names)')
    parser.add_argument('--ip', action='append', default=[],
                        help='also valid for this IP address (optional; names are preferred)')
    parser.add_argument('--out-dir', default=str(DEFAULT_DIR),
                        help='folder for server.crt and server.key (default: backend/tls)')
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS)
    parser.add_argument('--force', action='store_true', help='replace an existing certificate')
    args = parser.parse_args(argv)
    if not 1 <= args.days <= 3650:
        print('--days must be from 1 to 3650.', file=sys.stderr)
        return 2
    try:
        cert, key, fp = write(args.out_dir, args.name, args.ip, args.days, args.force)
    except CertError as err:
        print(f'No certificate made: {err}', file=sys.stderr)
        return 2
    print(f'Certificate (public, copy to clients): {cert}')
    print(f'Private key (SECRET, keep on this laptop only): {key}')
    print(f'Valid for: {", ".join(check_names(args.name))}, localhost, 127.0.0.1'
          + (f', {", ".join(args.ip)}' if args.ip else ''))
    print(f'SHA-256 fingerprint: {fp}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
