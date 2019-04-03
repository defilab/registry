import base64
import binascii
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import uuid

def load_crt(crt_str):
    return x509.load_pem_x509_certificate(
        data=crt_str.encode(),
        backend=default_backend()
    )

def load_csr(csr_str):
    return x509.load_pem_x509_csr(
        data=csr_str.encode(),
        backend=default_backend()
    )

def load_key(key_str):
    return serialization.load_pem_private_key(
        data=key_str.encode(),
        password=None,
        backend=default_backend()
    )

def calculate_signature(private_key_str, msg_str):
    key = load_key(private_key_str)
    signature = key.sign(
        msg_str.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature)

def verify_signature(crt_str, signature, msg_str):
    signature = base64.b64decode(signature)
    public_key = load_crt(crt_str).public_key()
    return public_key.verify(
        signature,
        msg_str.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def sign_csr(csr, ca_crt, ca_pkey):
    crt = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_crt.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        uuid.uuid4().int
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365 * 10)
    ).add_extension(
        extension=x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=True, data_encipherment=True,
            key_agreement=False, encipher_only=False, decipher_only=False,
            key_cert_sign=False, crl_sign=False
        ),
        critical=True
    ).add_extension(
        extension=x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pkey.public_key()),
        critical=False
    ).sign(
        private_key=ca_pkey,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    fingerprint = binascii.hexlify(crt.fingerprint(hashes.SHA1())).decode()
    return fingerprint, crt.public_bytes(encoding=serialization.Encoding.PEM).decode('ascii')
