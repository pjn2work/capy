#!/usr/bin/env python3

__author__ = "Pedro Nunes <pjn2work@google.com>"


import re
from typing import Union, Tuple
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes, CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def generate_ssh_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def decode_key(key_data_str: str) -> rsa.RSAPrivateKey:
    if key_data_str.count("\n") < 2:
        key_data_str = convert_str_to_pem(key_data_str)
    return load_pem_private_key(key_data_str.encode("utf-8"), None, default_backend())


# both strings, one in text-wall PEM format, other in str
def convert_keypair_to_pem_format(key: rsa.RSAPrivateKey) -> Tuple[str, str]:
    private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption()).decode("utf-8")
    public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    return private_key, public_key


def create_subject(C="PT", ST="Lisboa", L="Santo Antonio", O="ACME", OU="qa", CN="acme.com") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
        x509.NameAttribute(NameOID.COUNTRY_NAME, C),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST),
        x509.NameAttribute(NameOID.LOCALITY_NAME, L)])


def create_subject_from_dict(subject_dict: dict) -> x509.Name:
    _ds = dict(C="PT", ST="Lisboa", L="Santo Antonio", O="ACME", OU="qa", CN="acme.com")
    for k, v in subject_dict.items():
        if str(k).upper() in _ds:
            _ds[str(k).upper()] = v
    return create_subject(**_ds)


def convert_subject_to_dict(subject_name: x509.Name) -> dict:
    return {field.rfc4514_string().split("=")[0]: field.value for field in subject_name}


def create_extension_dns_list(dns_text_list: list) -> x509.SubjectAlternativeName:
    # x509.SubjectAlternativeName([x509.DNSName(u"mysite.com"), x509.DNSName(u"www.mysite.com"), ...])
    return x509.SubjectAlternativeName([x509.DNSName(dns_name) for dns_name in dns_text_list])


def generate_csr(subject: x509.Name,
                 sign_key: CertificateIssuerPrivateKeyTypes,
                 dns_text_list: list = None) -> x509.CertificateSigningRequest:
    if dns_text_list is None:
        dns_text_list = []
    return x509.CertificateSigningRequestBuilder()\
        .subject_name(subject) \
        .add_extension(create_extension_dns_list(dns_text_list), critical=False) \
        .sign(sign_key, hashes.SHA256(), default_backend())


# text wall of CSR
def convert_csr_to_pem_format(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')


# text wall with 64 chars length each row
def convert_cert_to_pem_format(cert: x509.Certificate) -> str:
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')


# returns in pem format
def generate_cert_from_csr(issuer_subject: x509.Name,
                           csr_data_str: str,
                           sign_key: rsa.RSAPrivateKey,
                           days: int = 365,
                           not_valid_before=datetime.utcnow(),
                           return_in_pem_format: bool = True):
    if csr_data_str.count("\n") < 2:
        csr_data_str = convert_str_to_pem(csr_data_str)

    csr = x509.load_pem_x509_csr(csr_data_str.encode("utf-8"), default_backend())
    cert = generate_cert(issuer_subject, csr.subject, csr.public_key(), sign_key, days=days, is_ca=False, not_valid_before=not_valid_before)

    if return_in_pem_format:
        return convert_cert_to_pem_format(cert)
    return cert


def generate_cert(issuer: x509.Name,
                  subject: x509.Name,
                  public_key: CertificatePublicKeyTypes,
                  sign_key: CertificateIssuerPrivateKeyTypes,
                  days: int = 365,
                  is_ca: bool = False,
                  path_length: Union[int, None] = None,
                  not_valid_before: datetime = datetime.utcnow(),
                  return_in_pem_format: bool = False) -> Union[x509.Certificate, str]:
    cert = x509.CertificateBuilder(issuer_name=issuer,
                                   subject_name=subject,
                                   public_key=public_key,
                                   serial_number=x509.random_serial_number(),
                                   not_valid_before=not_valid_before,
                                   not_valid_after=not_valid_before + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=True) \
        .sign(sign_key, hashes.SHA256(), default_backend())

    if return_in_pem_format:
        return convert_cert_to_pem_format(cert)
    return cert


def decode_csr(csr_data_str: str) -> x509.CertificateSigningRequest:
    if csr_data_str.count("\n") < 2:
        csr_data_str = convert_str_to_pem(csr_data_str)
    return x509.load_pem_x509_csr(csr_data_str.encode("utf-8"), default_backend())


def decode_cert(cert_data_str: str) -> x509.Certificate:
    if cert_data_str.count("\n") < 2:
        cert_data_str = convert_str_to_pem(cert_data_str)
    return x509.load_pem_x509_certificate(cert_data_str.encode("utf-8"), default_backend())


def get_subject_dict_from_csr_str(csr_data_str: str) -> dict:
    return convert_subject_to_dict(decode_csr(csr_data_str).subject)


def get_subject_dict_from_cert_str(cert_data_str: str) -> dict:
    return convert_subject_to_dict(decode_cert(cert_data_str).subject)


# text wall with 64 chars length each row
def convert_str_to_pem(data: str) -> str:
    re_groups = re.search(r'-----BEGIN (.+)-----(.*?)-----END .+-----', data)
    cert_type = re_groups.group(1)
    cert_data = re_groups.group(2)

    pd_res = ""
    while len(cert_data) > 64:
        pd_res = "\n".join((pd_res, cert_data[:64]))
        cert_data = cert_data[64:]
    pd_res = "\n".join((pd_res, cert_data))

    return f"-----BEGIN {cert_type}-----{pd_res}\n-----END {cert_type}-----"


# only one row string
def convert_pem_to_str(data: str) -> str:
    return data.replace("\n", "")
