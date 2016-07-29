# crlbuilder API Documentation

### `pem_armor_crl()` function

> ```python
> def pem_armor_crl(certificate_list):
>     """
>     :param certificate_list:
>         An asn1crypto.crl.CertificateList object of the CRL to armor.
>         Typically this is obtained from CertificateListBuilder.build().
>
>     :return:
>         A byte string of the PEM-encoded CRL
>     """
> ```
>
> Encodes a CRL into PEM format

### `CertificateListBuilder()` class

> ##### constructor
>
> > ```python
> > def __init__(self, url, issuer, crl_number):
> >     """
> >     :param url:
> >         A unicode string of the URL the CRL is published at. This must
> >         match the URL set on any certificates issued by the certificate
> >         issuer for the CRL to be valid.
> >
> >     :param issuer:
> >         An asn1crypto.x509.Certificate object of the issuer of the CRL. If
> >         generating an indirect CRL, the .certificate_issuer attribute
> >         should be set to the asn1crypto.x509.Certificate object that issued
> >         the certificates covered by the CRL.
> >
> >     :param crl_number:
> >         An integer of a monotonically increasing CRL number for the issuer
> >     """
> > ```
> >
> > Unless changed, certificate lists will use SHA-256 for the signature,
> > and will be valid from the moment created for one week.
> >
> > Supports indirect CRLs, but only for a single issuer.
>
> ##### `.url` attribute
>
> > A unicode string of where the CRL is hosted
>
> ##### `.issuer` attribute
>
> > An asn1crypto.x509.Certificate object of the issuer. Used to populate
> > both the issuer field, but also the authority key identifier extension.
> >
> > If the (CRL) issuer is not the issuer of the certificates (in which
> > case the CRL is known as an indirect CRL), the .certificate_issuer
> > attribute must be set to Certificate that issued the certificates.
>
> ##### `.certificate_issuer` attribute
>
> > An asn1crypto.x509.Certificate object of the issuer of the certificates.
> > This should only be set if the issuer of the CRL is not the issuer of
> > the certificates (in which case the CRL is known as an indirect CRL).
>
> ##### `.crl_number` attribute
>
> > An integer that is monotonically increased for each published CRL. Delta
> > CRLs must use CRL numbers from the same set as the complete CRL, but
> > must use distinct values.
>
> ##### `.this_update` attribute
>
> > A datetime.datetime object of when the certificate list was created.
>
> ##### `.next_update` attribute
>
> > A datetime.datetime object of when the certificate list will next be
> > updated.
>
> ##### `.hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when signing the
> > certificate - "sha1" (not recommended), "sha256" or "sha512".
>
> ##### `.delta_of` attribute
>
> > None or an integer - if an integer, contains the CRL number of the
> > complete CRL this delta was created from
>
> ##### `.delta_crl_url` attribute
>
> > Location of the delta CRL for the certificate. Will be one of the
> > following types:
> >
> >  - None for no delta CRL
> >  - A unicode string of the URL to the delta CRL for this certificate
>
> ##### `.issuer_certificate_url` attribute
>
> > None or a unicode string of the URL to download the issuer's certificate
> > from. This is mostly useful when generating an indirect CRL, since
> > clients will likely not have a copy of the issuer's certificate.
> >
> > The URL should serve the user the DER encoded certificate with the
> > mime type of application/pkix-cert.
>
> ##### `.add_certificate()` method
>
> > ```python
> > def add_certificate(self, serial_number, revocation_date, reason):
> >     """
> >     :param serial_number:
> >         The serial number of the revoked certificate
> >
> >     :param revocation_date:
> >         A datetime.datetime object of when the certificate was revoked
> >
> >     :param reason:
> >         A unicode string of one of:
> >
> >          - "key_compromise" - when a private key is compromised
> >          - "ca_compromise" - when the CA issuing the certificate is compromised
> >          - "affiliation_changed" - when the certificate subject name changed
> >          - "superseded" - when the certificate was replaced with a new one
> >          - "cessation_of_operation" - when the certificate is no longer needed
> >          - "certificate_hold" - when the certificate is temporarily invalid
> >          - "remove_from_crl" - only delta CRLs - when temporary hold is removed
> >          - "privilege_withdrawn" - one of the usages for a certificate was removed
> >     """
> > ```
> >
> > Adds a certificate to the list of revoked certificates
>
> ##### `.set_extension()` method
>
> > ```python
> > def set_extension(self, name, value):
> >     """
> >     :param name:
> >         A unicode string of an extension id name from
> >         asn1crypto.crl.TBSCertListExtensionId
> >
> >     :param value:
> >         A value object per the specs defined by
> >         asn1crypto.crl.TBSCertListExtension
> >     """
> > ```
> >
> > Sets the value for an extension using a fully constructed
> > asn1crypto.core.Asn1Value object. Normally this should not be needed,
> > and the convenience attributes should be sufficient.
> >
> > See the definition of asn1crypto.crl.TBSCertListExtension to determine
> > the appropriate object type for a given extension. Extensions are marked
> > as critical when RFC5280 indicates so.
>
> ##### `.build()` method
>
> > ```python
> > def build(self, issuer_private_key):
> >     """
> >     :param issuer_private_key:
> >         An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
> >         object for the private key of the CRL issuer
> >
> >     :return:
> >         An asn1crypto.crl.CertificateList object of the newly signed CRL
> >     """
> > ```
> >
> > Validates the certificate list information, constructs the ASN.1
> > structure and then signs it
