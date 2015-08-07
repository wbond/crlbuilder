# crlbuilder Documentation

*crlbuilder* is a Python library for constructing certificate revocation lists
(CRLs). It provides a high-level interface with knowledge of RFC 5280 to
produce valid, correct CRLs without terrible APIs or hunting through RFCs.

Since its only dependencies are the
[*asn1crypto*](https://github.com/wbond/asn1crypto#readme) and
[*oscrypto*](https://github.com/wbond/oscrypto#readme) libraries, it is
easy to install and use on Windows, OS X, Linux and the BSDs.

The documentation consists of the following topics:

 - [Basic Usage](#basic-usage)
 - [Indirect CRLs](#indirect-crls)
 - [API Documentation](api.md)

## Basic Usage

A standard CRL requires the URL of where the CRL will be hosted, the
certificate of the CA issuing the CRL and an integer of the CRL number. The
CRL number must an integer that is increased each time the CRL is updated.

By default, CRLs are marked valid for 7 days from the second it is generated.
This can be changed by setting the `this_update` and `next_update` attributes.

For every certificate that has been revoked, call the `.add_certificate()`
method, passing the certificate's serial number, revocation date and reason.
The reason should be one of options listed at
[CertificateListBuilder.add_certificate](#api.md#add_certificate-method).

```python
from datetime import datetime

from asn1crypto.util import timezone
from oscrypto import asymmetric
from crlbuilder import CertificateListBuilder


private_key = asymmetric.load_private_key('/path/to/root.key'), 'password123')
certificate = asymmetric.load_certificate('/path/to/root.crt'))

builder = CertificateListBuilder(
    'http://crl.example.com',
    certificate,
    1000
)

revoked_cert_serial = 1234568
revoked_time = datetime(2015, 8, 1, tzinfo=timezone.utc)
builder.add_certificate(revoked_cert_serial, revoked_time, 'key_compromise')

certificate_list = builder.build(private_key)

with open('/path/to/env/root.crl', 'wb') as f:
    f.write(certificate_list.dump())
```

## Indirect CRLs

An indirect CRL is when the CRL is issued by a certificate other than the CA
certificate. This allows delegating the signing to a certificate created
specifically for issuing CRLs.

For an indirect CRL to be correct, the CA certificate used to issue the
certificates covered by the CRL must be set to the `.certificate_issuer`
attribute.

Additionally, a URL for the user to download the CRL issuer certificate should
be set to the `.issuer_certificate_url` attribute. This URL should serve the DER
encoded certificate with a mime type of `application/pkix-cert`.

```python
from datetime import datetime

from asn1crypto.util import timezone
from oscrypto import asymmetric
from crlbuilder import CertificateListBuilder


root_certificate = asymmetric.load_certificate('/path/to/root.crt'))
crl_issuer_private_key = asymmetric.load_private_key('/path/to/crl_issuer.key'), 'password123')
crl_issuer_certificate = asymmetric.load_certificate('/path/to/crl_issuer.crt'))


builder = CertificateListBuilder(
    'http://crl.example.com',
    crl_issuer_certificate,
    1000
)
builder.certificate_issuer = root_certificate
builder.issuer_certificate_url = 'http://crl.example.com/crl_issuer.crt'

revoked_cert_serial = 1234568
revoked_time = datetime(2015, 8, 1, tzinfo=timezone.utc)
builder.add_certificate(revoked_cert_serial, revoked_time, 'key_compromise')

certificate_list = builder.build(crl_issuer_private_key)

with open('/path/to/env/root.crl', 'wb') as f:
    f.write(certificate_list.dump())
```
