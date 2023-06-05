from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

# ------------------------------------------------------------------------------#


def generate_certificate(
    common_name: str,
    organization_name: str,
    country_name: str,
    private_key_path: str,
    certificate_path: str,
    validity_period: int,
    issuer_name="",
    issuer_private_key="",
    issuer_certificate=None,
):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Create a subject for the certificate
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        ]
    )

    # Create a certificate builder
    builder = x509.CertificateBuilder().subject_name(subject)

    if issuer_certificate:
        builder = builder.issuer_name(issuer_certificate.subject)
    else:
        builder = builder.issuer_name(subject)

    # Set validity for the certificate
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=validity_period)

    builder = builder.not_valid_before(valid_from).not_valid_after(valid_to)

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Add the public key to the certificate builder
    builder = builder.public_key(public_key)

    if issuer_certificate:
        # Create AuthorityKeyIdentifier extension manually
        issuer_subject_key_identifier = (
            issuer_certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value
        )

        authority_key_identifier = x509.AuthorityKeyIdentifier(
            key_identifier=issuer_subject_key_identifier,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
        builder = builder.add_extension(authority_key_identifier, critical=False)
        certificate = builder.sign(
            private_key=issuer_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    else:
        # Self-sign the root certificate
        builder = builder.serial_number(x509.random_serial_number()).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

    # Serialize the private key and certificate to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    # Write the private key and certificate to files
    with open(private_key_path, "wb") as f:
        f.write(private_key_pem)
    with open(certificate_path, "wb") as f:
        f.write(certificate_pem)
    # return private_key_pem, certificate_pem
    return private_key, certificate


# ------------------------------------------------------------------------------#


"""
def generate_certificate(subject_name: str, issuer_name: str, issuer_private_key: str,
                         private_key_path: str, certificate_path: str,
                         issuer_certificate=None
                         ):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create a subject for the certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    # Create a certificate builder
    builder = x509.CertificateBuilder().subject_name(subject)

    if issuer_certificate:
        builder = builder.issuer_name(issuer_certificate.subject)
    else:
        builder = builder.issuer_name(issuer_name)

    # Set validity for the certificate
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=365)

    builder = builder.not_valid_before(valid_from).not_valid_after(valid_to)

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Add the public key to the certificate builder
    builder = builder.public_key(public_key)

    if issuer_certificate:
        # Add the issuer's certificate as the signer
        builder = builder.serial_number(x509.random_serial_number()).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_certificate),
            critical=False
        )
        certificate = builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256(),
                                   backend=default_backend())
    else:
        # Self-sign the root certificate
        builder = builder.serial_number(x509.random_serial_number()).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),
                                   backend=default_backend())

    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    with open(certificate_path, 'wb') as f:
        f.write(certificate)
"""
# ------------------------------------------------------------------------------#

# # Usage
# root_subject_name = 'Root Certificate'
# intermediate_subject_names = ['Intermediate Certificate 1', 'Intermediate Certificate 2']

# generate_certificate_chain(root_subject_name, intermediate_subject_names)
"""
{
    "root": {
        "common_name": "Root Certificate",
        "organization_name": "uvt",
        "country_name": "ro",
        "private_key_path": "root_private_key.pem",
        "certificate_path": "root_certificate.pem",
        "validity_period": 365,
    },
    "1": {
        "common_name": "Intermediate Certificate 1",
        "organization_name": "uvt",
        "country_name": "ro",
        "private_key_path": "priv-1.pem",
        "certificate_path": "cert-1.pem",
        "validity_period": 365,
        "issuer_name": "Root Certificate",
        "issuer_private_key": "root_private_key.pem",
        "issuer_certificate": "root_certificate.pem"
    },
    "2": {
        "common_name": "Intermediate Certificate 2",
        "organization_name": "uvt",
        "country_name": "ro",
        "private_key_path": "priv-2.pem",
        "certificate_path": "cert-2.pem",
        "validity_period": 365,
        "issuer_name": "Intermediate Certificate 1",
        "issuer_private_key": "priv-1.pem",
        "issuer_certificate": "cert-1.pem"
        },
    # generate one more final intermediate certificate
    "3": {
        "common_name": "Final Intermediate Certificate",
        "organization_name": "uvt",
        "country_name": "ro",
        "private_key_path": "priv-3.pem",
        "certificate_path": "cert-3.pem",
        "validity_period": 365,
        "issuer_name": "Intermediate Certificate 2",
        "issuer_private_key": "priv-2.pem",
        "issuer_certificate": "cert-2.pem"
    },
}
"""


def generate_certificate_chain(
    certificate_chain={}, issuer_private_key=None, issuer_certificate=None
):
    for certificate in certificate_chain:
        print(certificate.get("id"))
        if certificate.get("id") == "root":
            # Generate the root certificate
            root_private_key, root_certificate = generate_certificate(
                certificate.get("common_name"),
                certificate.get("organization_name"),
                certificate.get("country_name"),
                certificate.get("private_key_path"),
                certificate.get("certificate_path"),
                certificate.get("validity_period"),
            )

            # Set the issuer private key and certificate to the root certificate
            issuer_private_key = root_private_key
            issuer_certificate = root_certificate
        else:
            # Generate intermediate certificates and chain them to the root certificate
            print(issuer_certificate.subject)
            print(issuer_private_key)
            print(issuer_certificate)
            private_key, certificate = generate_certificate(
                certificate.get("common_name"),
                certificate.get("organization_name"),
                certificate.get("country_name"),
                certificate.get("private_key_path"),
                certificate.get("certificate_path"),
                certificate.get("validity_period"),
                issuer_name=issuer_certificate.subject,
                issuer_private_key=issuer_private_key,
                issuer_certificate=issuer_certificate,
            )

            issuer_private_key = private_key
            issuer_certificate = certificate

            # Save the intermediate certificate to a file
            with open(certificate.get("certificate_path"), "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            # Save the intermediate private key to a file
            with open(certificate.get("private_key_path"), "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

    print("Certificate chain generated successfully!")


# ------------------------------------------------------------------------------#


def extend_certificate_life(
    certificate_path, private_key_path, extended_certificate_path, validity_days
):
    # Load the certificate and private key
    with open(certificate_path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Calculate the new validity period
    current_not_before = certificate.not_valid_before
    current_not_after = certificate.not_valid_after

    extended_not_before = current_not_before
    extended_not_after = current_not_after + datetime.timedelta(days=validity_days)

    # Create a certificate builder with the updated validity period
    builder = (
        x509.CertificateBuilder()
        .subject_name(certificate.subject)
        .issuer_name(certificate.issuer)
    )
    builder = builder.not_valid_before(extended_not_before).not_valid_after(
        extended_not_after
    )

    # Copy over the existing extensions from the original certificate
    for extension in certificate.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    # Sign the new certificate with the private key
    extended_certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Serialize the extended certificate
    extended_certificate_pem = extended_certificate.public_bytes(
        serialization.Encoding.PEM
    )

    # Save the extended certificate to a file
    with open(extended_certificate_path, "wb") as f:
        f.write(extended_certificate_pem)

    print("Certificate extended successfully!")


# ------------------------------------------------------------------------------#


def revoke_certificate(certificate_path, private_key_path, crl_path, revoked_cert_path):
    # Load the certificate and private key
    with open(certificate_path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Create a new CRL or load an existing one
    try:
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read(), default_backend())
    except FileNotFoundError:
        crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
            certificate.issuer
        )

        crl = (
            crl_builder.last_update(certificate.not_valid_before)
            .next_update(certificate.not_valid_after)
            .build(private_key)
        )

    # Add the revoked certificate to the CRL
    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(certificate.serial_number)
        .build(default_backend())
    )
    crl = crl.add_revoked_certificate(revoked_cert)

    # Serialize the CRL
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    # Save the updated CRL to a file
    with open(crl_path, "wb") as f:
        f.write(crl_pem)

    # Save the revoked certificate separately (optional)
    with open(revoked_cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("Certificate revoked successfully!")


# ------------------------------------------------------------------------------#

# # Usage
# certificate_path = 'certificate.pem'
# private_key_path = 'private_key.pem'
# crl_path = 'crl.pem'
# revoked_cert_path = 'revoked_certificate.pem'

# Usage
# certificate_path = 'certificate.pem'
# private_key_path = 'private_key.pem'
# extended_certificate_path = 'extended_certificate.pem'
# validity_days = 30

# extend_certificate_life(certificate_path, private_key_path, extended_certificate_path, validity_days)