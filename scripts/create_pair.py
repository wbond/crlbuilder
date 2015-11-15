# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from oscrypto import asymmetric
from certbuilder import CertificateBuilder


fixtures_dir = os.path.join(os.path.dirname(__file__), '..', 'tests', 'fixtures')

root_ca_public_key, root_ca_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open(os.path.join(fixtures_dir, 'root.key'), 'wb') as f:
    f.write(asymmetric.dump_private_key(root_ca_private_key, 'password123', target_ms=20))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'CodexNS Root CA 1',
    },
    root_ca_public_key
)
builder.self_signed = True
builder.end_entity = False
root_ca_certificate = builder.build(root_ca_private_key)

with open(os.path.join(fixtures_dir, 'root.crt'), 'wb') as f:
    f.write(asymmetric.dump_certificate(root_ca_certificate))


root_crl_public_key, root_crl_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open(os.path.join(fixtures_dir, 'crl_issuer.key'), 'wb') as f:
    f.write(asymmetric.dump_private_key(root_crl_private_key, 'password123', target_ms=20))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'CodexNS Root CA 1 CRL Issuer',
    },
    root_crl_public_key
)
builder.key_usage = set(['crl_signing'])
builder.extended_key_usage = None
builder.issuer = root_ca_certificate
root_crl_certificate = builder.build(root_ca_private_key)

with open(os.path.join(fixtures_dir, 'crl_issuer.crt'), 'wb') as f:
    f.write(asymmetric.dump_certificate(root_crl_certificate))
