# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
from datetime import datetime

from asn1crypto import crl
from asn1crypto.util import timezone
from oscrypto import asymmetric
from crlbuilder import CertificateListBuilder

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CertificateListBuilderTests(unittest.TestCase):

    def test_build_basic_crl(self):
        root_private_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'root.key'), 'password123')
        root_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'root.crt'))

        builder = CertificateListBuilder(
            'http://crl.example.com',
            root_certificate,
            50000
        )
        revoked_at = datetime(2015, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        builder.add_certificate(29232181, revoked_at, 'key_compromise')
        certificate_list = builder.build(root_private_key)
        der_bytes = certificate_list.dump()

        new_cert_list = crl.CertificateList.load(der_bytes)
        tbs_cert_list = new_cert_list['tbs_cert_list']
        revoked_certificates = tbs_cert_list['revoked_certificates']

        now = datetime.now(timezone.utc)

        self.assertEqual('v3', tbs_cert_list['version'].native)
        self.assertEqual('rsassa_pkcs1v15', tbs_cert_list['signature'].signature_algo)
        self.assertEqual('sha256', tbs_cert_list['signature'].hash_algo)
        self.assertEqual(root_certificate.asn1.subject, tbs_cert_list['issuer'])
        self.assertEqual(root_certificate.asn1.subject.sha256, tbs_cert_list['issuer'].sha256)
        self.assertGreaterEqual(now, tbs_cert_list['this_update'].native)
        self.assertLess(now, tbs_cert_list['next_update'].native)
        self.assertEqual(set(['issuing_distribution_point']), new_cert_list.critical_extensions)

        self.assertEqual(1, len(revoked_certificates))
        revoked_cert = revoked_certificates[0]
        self.assertEqual(29232181, revoked_cert['user_certificate'].native)
        self.assertEqual(revoked_at, revoked_cert['revocation_date'].native)
        self.assertEqual(set(), revoked_cert.critical_extensions)
        self.assertEqual('key_compromise', revoked_cert.crl_reason_value.native)
        self.assertEqual(None, revoked_cert.invalidity_date_value)
        self.assertEqual(None, revoked_cert.certificate_issuer_value)
        self.assertEqual(None, revoked_cert.issuer_name)

        self.assertEqual(None, new_cert_list.issuer_alt_name_value)
        self.assertEqual(50000, new_cert_list.crl_number_value.native)
        self.assertEqual(None, new_cert_list.delta_crl_indicator_value)
        self.assertEqual('full_name', new_cert_list.issuing_distribution_point_value['distribution_point'].name)
        self.assertEqual(
            'uniform_resource_identifier',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].name
        )
        self.assertEqual(
            'http://crl.example.com',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].native
        )
        self.assertEqual(root_certificate.asn1.key_identifier, new_cert_list.authority_key_identifier)
        self.assertEqual(None, new_cert_list.freshest_crl_value)
        self.assertEqual(None, new_cert_list.authority_information_access_value)

    def test_build_indirect_crl(self):
        root_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'root.crt'))

        crl_issuer_private_key = asymmetric.load_private_key(
            os.path.join(fixtures_dir, 'crl_issuer.key'),
            'password123'
        )
        crl_issuer_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'crl_issuer.crt'))

        builder = CertificateListBuilder(
            'http://crl.example.com',
            crl_issuer_certificate,
            50000
        )
        builder.certificate_issuer = root_certificate
        builder.issuer_certificate_url = 'http://download.example.com/crl_issuer'
        builder.delta_crl_url = 'http://crl.example.com/delta'

        revoked_at = datetime(2015, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        builder.add_certificate(29232181, revoked_at, 'key_compromise')

        revoked_at_2 = datetime(2014, 12, 29, 8, 0, 0, tzinfo=timezone.utc)
        builder.add_certificate(12345678, revoked_at_2, 'key_compromise')

        certificate_list = builder.build(crl_issuer_private_key)
        der_bytes = certificate_list.dump()

        new_cert_list = crl.CertificateList.load(der_bytes)
        tbs_cert_list = new_cert_list['tbs_cert_list']
        revoked_certificates = tbs_cert_list['revoked_certificates']

        now = datetime.now(timezone.utc)

        self.assertEqual('v3', tbs_cert_list['version'].native)
        self.assertEqual('rsassa_pkcs1v15', tbs_cert_list['signature'].signature_algo)
        self.assertEqual('sha256', tbs_cert_list['signature'].hash_algo)
        self.assertEqual(crl_issuer_certificate.asn1.subject, tbs_cert_list['issuer'])
        self.assertEqual(crl_issuer_certificate.asn1.subject.sha256, tbs_cert_list['issuer'].sha256)
        self.assertGreaterEqual(now, tbs_cert_list['this_update'].native)
        self.assertLess(now, tbs_cert_list['next_update'].native)
        self.assertEqual(set(['issuing_distribution_point']), new_cert_list.critical_extensions)

        self.assertEqual(2, len(revoked_certificates))

        revoked_cert_1 = revoked_certificates[0]
        self.assertEqual(29232181, revoked_cert_1['user_certificate'].native)
        self.assertEqual(revoked_at, revoked_cert_1['revocation_date'].native)
        self.assertEqual(set(['certificate_issuer']), revoked_cert_1.critical_extensions)
        self.assertEqual('key_compromise', revoked_cert_1.crl_reason_value.native)
        self.assertEqual(None, revoked_cert_1.invalidity_date_value)
        self.assertEqual('directory_name', revoked_cert_1.certificate_issuer_value[0].name)
        self.assertNotEqual(None, revoked_cert_1.certificate_issuer_value)
        self.assertEqual(root_certificate.asn1.subject, revoked_cert_1.issuer_name)

        revoked_cert_2 = revoked_certificates[1]
        self.assertEqual(12345678, revoked_cert_2['user_certificate'].native)
        self.assertEqual(revoked_at_2, revoked_cert_2['revocation_date'].native)
        self.assertEqual(set(), revoked_cert_2.critical_extensions)
        self.assertEqual('key_compromise', revoked_cert_2.crl_reason_value.native)
        self.assertEqual(None, revoked_cert_2.invalidity_date_value)
        self.assertEqual(None, revoked_cert_2.certificate_issuer_value)
        self.assertEqual(None, revoked_cert_2.issuer_name)

        self.assertEqual(None, new_cert_list.issuer_alt_name_value)
        self.assertEqual(50000, new_cert_list.crl_number_value.native)
        self.assertEqual(None, new_cert_list.delta_crl_indicator_value)
        self.assertEqual('full_name', new_cert_list.issuing_distribution_point_value['distribution_point'].name)
        self.assertEqual(
            'uniform_resource_identifier',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].name
        )
        self.assertEqual(
            'http://crl.example.com',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].native
        )
        self.assertEqual(crl_issuer_certificate.asn1.key_identifier, new_cert_list.authority_key_identifier)
        self.assertEqual('http://crl.example.com/delta', new_cert_list.delta_crl_distribution_points[0].url)
        self.assertEqual(['http://download.example.com/crl_issuer'], new_cert_list.issuer_cert_urls)

    def test_build_delta_crl(self):
        root_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'root.crt'))

        crl_issuer_private_key = asymmetric.load_private_key(
            os.path.join(fixtures_dir, 'crl_issuer.key'),
            'password123'
        )
        crl_issuer_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'crl_issuer.crt'))

        builder = CertificateListBuilder(
            'http://crl.example.com/delta',
            crl_issuer_certificate,
            50001
        )
        builder.certificate_issuer = root_certificate
        builder.issuer_certificate_url = 'http://download.example.com/crl_issuer'
        builder.delta_of = 50000

        certificate_list = builder.build(crl_issuer_private_key)
        der_bytes = certificate_list.dump()

        new_cert_list = crl.CertificateList.load(der_bytes)
        tbs_cert_list = new_cert_list['tbs_cert_list']
        revoked_certificates = tbs_cert_list['revoked_certificates']

        now = datetime.now(timezone.utc)

        self.assertEqual('v3', tbs_cert_list['version'].native)
        self.assertEqual('rsassa_pkcs1v15', tbs_cert_list['signature'].signature_algo)
        self.assertEqual('sha256', tbs_cert_list['signature'].hash_algo)
        self.assertEqual(crl_issuer_certificate.asn1.subject, tbs_cert_list['issuer'])
        self.assertEqual(crl_issuer_certificate.asn1.subject.sha256, tbs_cert_list['issuer'].sha256)
        self.assertGreaterEqual(now, tbs_cert_list['this_update'].native)
        self.assertLess(now, tbs_cert_list['next_update'].native)
        self.assertEqual(set(['issuing_distribution_point', 'delta_crl_indicator']), new_cert_list.critical_extensions)

        self.assertEqual(0, len(revoked_certificates))

        self.assertEqual(None, new_cert_list.issuer_alt_name_value)
        self.assertEqual(50001, new_cert_list.crl_number_value.native)
        self.assertEqual(50000, new_cert_list.delta_crl_indicator_value.native)
        self.assertEqual('full_name', new_cert_list.issuing_distribution_point_value['distribution_point'].name)
        self.assertEqual(
            'uniform_resource_identifier',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].name
        )
        self.assertEqual(
            'http://crl.example.com/delta',
            new_cert_list.issuing_distribution_point_value['distribution_point'].chosen[0].native
        )
        self.assertEqual(crl_issuer_certificate.asn1.key_identifier, new_cert_list.authority_key_identifier)
        self.assertEqual([], new_cert_list.delta_crl_distribution_points)
        self.assertEqual(['http://download.example.com/crl_issuer'], new_cert_list.issuer_cert_urls)
