# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta
import inspect
import re
import sys
import textwrap

from asn1crypto import x509, keys, crl, pem
from asn1crypto.util import timezone
from oscrypto import asymmetric

if sys.version_info < (3,):
    int_types = (int, long)  # noqa
    str_cls = unicode  # noqa
    byte_cls = str
else:
    int_types = (int,)
    str_cls = str
    byte_cls = bytes


__version__ = '0.10.1'
__version_info__ = (0, 10, 1)


def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """

    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


def pem_armor_crl(certificate_list):
    """
    Encodes a CRL into PEM format

    :param certificate_list:
        An asn1crypto.crl.CertificateList object of the CRL to armor.
        Typically this is obtained from CertificateListBuilder.build().

    :return:
        A byte string of the PEM-encoded CRL
    """

    if not isinstance(certificate_list, crl.CertificateList):
        raise TypeError(_pretty_message(
            '''
            certificate_list must be an instance of
            asn1crypto.crl.CertificateList, not %s
            ''',
            _type_name(certificate_list)
        ))

    return pem.armor('X509 CRL', certificate_list.dump())


class CertificateListBuilder(object):

    _hash_algo = None
    _issuer = None
    _this_update = None
    _next_update = None
    _revoked_certificates = None
    _certificate_issuer = None

    _crl_number = None
    _delta_crl_indicator = None
    _issuing_distribution_point = None
    _freshest_crl = None
    _authority_key_identifier = None
    _authority_information_access = None

    _other_extensions = None

    _special_extensions = set([
        'crl_number',
        'delta_crl_indicator',
        'issuing_distribution_point',
        'freshest_crl',
        'authority_key_identifier',
        'authority_information_access',
    ])

    def __init__(self, url, issuer, crl_number):
        """
        Unless changed, certificate lists will use SHA-256 for the signature,
        and will be valid from the moment created for one week.

        Supports indirect CRLs, but only for a single issuer.

        :param url:
            A unicode string of the URL the CRL is published at. This must
            match the URL set on any certificates issued by the certificate
            issuer for the CRL to be valid.

        :param issuer:
            An asn1crypto.x509.Certificate object of the issuer of the CRL. If
            generating an indirect CRL, the .certificate_issuer attribute
            should be set to the asn1crypto.x509.Certificate object that issued
            the certificates covered by the CRL.

        :param crl_number:
            An integer of a monotonically increasing CRL number for the issuer
        """

        self.url = url
        self.issuer = issuer
        self.crl_number = crl_number

        self._hash_algo = 'sha256'
        self._revoked_certificates = []
        self._other_extensions = {}

    @property
    def url(self):
        """
        A unicode string of where the CRL is hosted
        """

        return self._issuing_distribution_point['distribution_point'].chosen[0].native

    @url.setter
    def url(self, value):
        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                url must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        if self._issuing_distribution_point is None:
            general_names = x509.GeneralNames([
                x509.GeneralName(
                    name='uniform_resource_identifier',
                    value=value
                )
            ])
            distribution_point_name = x509.DistributionPointName(
                name='full_name',
                value=general_names
            )
            self._issuing_distribution_point = crl.IssuingDistributionPoint({
                'distribution_point': distribution_point_name
            })
        else:
            distribution_point_name = self._issuing_distribution_point['distribution_point']
            general_names = distribution_point_name.chosen
            general_names[0] = x509.GeneralName(
                name='uniform_resource_identifier',
                value=value
            )

    @_writer
    def issuer(self, value):
        """
        An asn1crypto.x509.Certificate object of the issuer. Used to populate
        both the issuer field, but also the authority key identifier extension.

        If the (CRL) issuer is not the issuer of the certificates (in which
        case the CRL is known as an indirect CRL), the .certificate_issuer
        attribute must be set to Certificate that issued the certificates.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not is_oscrypto and not isinstance(value, x509.Certificate):
            raise TypeError(_pretty_message(
                '''
                issuer must be an instance of asn1crypto.x509.Certificate or
                oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        if value.key_identifier is None:
            raise ValueError(_pretty_message(
                '''
                issuer certificate must have a key identifier extension to be
                used for signing CRLs
                '''
            ))

        self._issuer = value

        self._authority_key_identifier = x509.AuthorityKeyIdentifier({
            'key_identifier': value.key_identifier
        })

    @_writer
    def certificate_issuer(self, value):
        """
        An asn1crypto.x509.Certificate object of the issuer of the certificates.
        This should only be set if the issuer of the CRL is not the issuer of
        the certificates (in which case the CRL is known as an indirect CRL).
        """

        if value is not None:
            is_oscrypto = isinstance(value, asymmetric.Certificate)
            if not is_oscrypto and not isinstance(value, x509.Certificate):
                raise TypeError(_pretty_message(
                    '''
                    certificate_issuer must be an instance of
                    asn1crypto.x509.Certificate or
                    oscrypto.asymmetric.Certificate, not %s
                    ''',
                    _type_name(value)
                ))

            if is_oscrypto:
                value = value.asn1

            if value.issuer_serial == self._issuer.issuer_serial:
                raise ValueError(_pretty_message(
                    '''
                    certificate_issuer is only to be used when the CRL and
                    certificate issuers are different keys
                    '''
                ))

        self._certificate_issuer = value

        self._issuing_distribution_point['indirect_crl'] = value is not None

    @_writer
    def crl_number(self, value):
        """
        An integer that is monotonically increased for each published CRL. Delta
        CRLs must use CRL numbers from the same set as the complete CRL, but
        must use distinct values.
        """

        if not isinstance(value, int_types):
            raise TypeError(_pretty_message(
                '''
                crl_number must be an integer, not %s
                ''',
                _type_name(value)
            ))

        self._crl_number = value

    @_writer
    def this_update(self, value):
        """
        A datetime.datetime object of when the certificate list was created.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                this_update must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._this_update = value

    @_writer
    def next_update(self, value):
        """
        A datetime.datetime object of when the certificate list will next be
        updated.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                next_update must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._next_update = value

    @_writer
    def hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when signing the
        certificate - "sha1" (not recommended), "sha256" or "sha512".
        """

        if value not in set(['sha1', 'sha256', 'sha512']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))

        self._hash_algo = value

    @property
    def delta_of(self):
        """
        None or an integer - if an integer, contains the CRL number of the
        complete CRL this delta was created from
        """

        return self._delta_crl_indicator

    @delta_of.setter
    def delta_of(self, value):
        if value is not None and not isinstance(value, int_types):
            raise TypeError(_pretty_message(
                '''
                delta_of must be an integer, not %s
                ''',
                _type_name(value)
            ))

        if self._freshest_crl is not None:
            raise ValueError(_pretty_message(
                '''
                delta_of can not be set if delta_crl_url is set
                '''
            ))

        self._delta_crl_indicator = value

    @property
    def delta_crl_url(self):
        """
        Location of the delta CRL for the certificate. Will be one of the
        following types:

         - None for no delta CRL
         - A unicode string of the URL to the delta CRL for this certificate
        """

        if self._freshest_crl is None:
            return None

        for distribution_point in self._freshest_crl:
            name = distribution_point['distribution_point']
            if name.name == 'full_name' and name.chosen[0].name == 'uniform_resource_identifier':
                return name.chosen[0].chosen.native

        return None

    @delta_crl_url.setter
    def delta_crl_url(self, value):
        if value is None:
            self._freshest_crl = None
            return

        if self._delta_crl_indicator is not None:
            raise ValueError(_pretty_message(
                '''
                delta_crl_url can not be set if delta_of is set
                '''
            ))

        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                delta_crl_url must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        general_names = x509.GeneralNames([
            x509.GeneralName(
                name='uniform_resource_identifier',
                value=value
            )
        ])
        distribution_point_name = x509.DistributionPointName(
            name='full_name',
            value=general_names
        )
        distribution_point = x509.DistributionPoint({
            'distribution_point': distribution_point_name
        })

        self._freshest_crl = x509.CRLDistributionPoints([distribution_point])

    @property
    def issuer_certificate_url(self):
        """
        None or a unicode string of the URL to download the issuer's certificate
        from. This is mostly useful when generating an indirect CRL, since
        clients will likely not have a copy of the issuer's certificate.

        The URL should serve the user the DER encoded certificate with the
        mime type of application/pkix-cert.
        """

        if self._authority_information_access is None:
            return None

        for ad in self._authority_information_access:
            method_is_ca = ad['access_method'].native == 'ca_issuers'
            location_is_uri = ad['access_location'].name == 'uniform_resource_identifier'
            if method_is_ca and location_is_uri:
                return ad['access_location'].native

        return None

    @issuer_certificate_url.setter
    def issuer_certificate_url(self, value):
        if value is not None and not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                issuer_certificate_url must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        self._authority_information_access = x509.AuthorityInfoAccessSyntax([
            {
                'access_method': 'ca_issuers',
                'access_location': x509.GeneralName(
                    name='uniform_resource_identifier',
                    value=value
                )
            }
        ])

    def add_certificate(self, serial_number, revocation_date, reason):
        """
        Adds a certificate to the list of revoked certificates

        :param serial_number:
            The serial number of the revoked certificate

        :param revocation_date:
            A datetime.datetime object of when the certificate was revoked

        :param reason:
            A unicode string of one of:

             - "key_compromise" - when a private key is compromised
             - "ca_compromise" - when the CA issuing the certificate is compromised
             - "affiliation_changed" - when the certificate subject name changed
             - "superseded" - when the certificate was replaced with a new one
             - "cessation_of_operation" - when the certificate is no longer needed
             - "certificate_hold" - when the certificate is temporarily invalid
             - "remove_from_crl" - only delta CRLs - when temporary hold is removed
             - "privilege_withdrawn" - one of the usages for a certificate was removed
        """

        if not isinstance(serial_number, int_types):
            raise TypeError(_pretty_message(
                '''
                serial_number must be an integer, not %s
                ''',
                _type_name(serial_number)
            ))

        if not isinstance(revocation_date, datetime):
            raise TypeError(_pretty_message(
                '''
                revocation_date must be an instance of datetime.datetime, not %s
                ''',
                _type_name(revocation_date)
            ))

        if not isinstance(reason, str_cls):
            raise TypeError(_pretty_message(
                '''
                reason must be a unicode string, not %s
                ''',
                _type_name(reason)
            ))

        valid_reasons = set([
            'key_compromise',
            'ca_compromise',
            'affiliation_changed',
            'superseded',
            'cessation_of_operation',
            'certificate_hold',
            'remove_from_crl',
            'privilege_withdrawn'
        ])
        if reason not in valid_reasons:
            raise ValueError(_pretty_message(
                '''
                reason must be one of "key_compromise", "ca_compromise",
                "affiliation_changed", "superseded", "cessation_of_operation",
                "certificate_hold", "remove_from_crl", "privilege_withdrawn",
                not %s
                ''',
                repr(reason)
            ))

        self._revoked_certificates.append(crl.RevokedCertificate({
            'user_certificate': serial_number,
            'revocation_date': x509.Time(name='utc_time', value=revocation_date),
            'crl_entry_extensions': [
                {
                    'extn_id': 'crl_reason',
                    'critical': False,
                    'extn_value': reason
                }
            ]
        }))

    def set_extension(self, name, value):
        """
        Sets the value for an extension using a fully constructed
        asn1crypto.core.Asn1Value object. Normally this should not be needed,
        and the convenience attributes should be sufficient.

        See the definition of asn1crypto.crl.TBSCertListExtension to determine
        the appropriate object type for a given extension. Extensions are marked
        as critical when RFC5280 indicates so.

        :param name:
            A unicode string of an extension id name from
            asn1crypto.crl.TBSCertListExtensionId

        :param value:
            A value object per the specs defined by
            asn1crypto.crl.TBSCertListExtension
        """

        extension = crl.TBSCertListExtension({
            'extn_id': name
        })
        # We use native here to convert OIDs to meaningful names
        name = extension['extn_id'].native
        spec = extension.spec('extn_value')

        if not isinstance(value, spec) and value is not None:
            raise TypeError(_pretty_message(
                '''
                value must be an instance of %s, not %s
                ''',
                _type_name(spec),
                _type_name(value)
            ))

        if name in self._special_extensions:
            setattr(self, '_%s' % name, value)
        else:
            if value is None:
                if name in self._other_extensions:
                    del self._other_extensions[name]
            else:
                self._other_extensions[name] = value

    def _determine_critical(self, name):
        """
        :param name:
            The extension to get the critical value for

        :return:
            A bool indicating the correct value of the critical flag for
            an extension, based on information from RFC5280. The
            correct value is based on the terminology SHOULD or MUST.
        """

        return {
            'issuer_alt_name': False,
            'authority_key_identifier': False,
            'crl_number': False,
            'delta_crl_indicator': True,
            'issuing_distribution_point': True,
            'freshest_crl': False,
            'authority_information_access': False,
        }.get(name, False)

    def build(self, issuer_private_key):
        """
        Validates the certificate list information, constructs the ASN.1
        structure and then signs it

        :param issuer_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key of the CRL issuer

        :return:
            An asn1crypto.crl.CertificateList object of the newly signed CRL
        """

        is_oscrypto = isinstance(issuer_private_key, asymmetric.PrivateKey)
        if not isinstance(issuer_private_key, keys.PrivateKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                issuer_private_key must be an instance of
                asn1crypto.keys.PrivateKeyInfo or
                oscrypto.asymmetric.PrivateKey, not %s
                ''',
                _type_name(issuer_private_key)
            ))

        if self._this_update is None:
            self._this_update = datetime.now(timezone.utc)

        if self._next_update is None:
            self._next_update = self._this_update + timedelta(days=7)

        signature_algo = issuer_private_key.algorithm
        if signature_algo == 'ec':
            signature_algo = 'ecdsa'

        signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        # For an indirect CRL we need to set the first
        if self._certificate_issuer and len(self._revoked_certificates) > 0:
            self._revoked_certificates[0]['crl_entry_extensions'].append({
                'extn_id': 'certificate_issuer',
                'critical': True,
                'extn_value': x509.GeneralNames([
                    x509.GeneralName(
                        name='directory_name',
                        value=self._certificate_issuer.subject
                    )
                ])
            })

        tbs_cert_list = crl.TbsCertList({
            'version': 'v3',
            'signature': {
                'algorithm': signature_algorithm_id
            },
            'issuer': self._issuer.subject,
            'this_update': x509.Time(name='utc_time', value=self._this_update),
            'next_update': x509.Time(name='utc_time', value=self._next_update),
            'revoked_certificates': crl.RevokedCertificates(self._revoked_certificates),
            'crl_extensions': extensions
        })

        if issuer_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif issuer_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif issuer_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        if not is_oscrypto:
            issuer_private_key = asymmetric.load_private_key(issuer_private_key)
        signature = sign_func(issuer_private_key, tbs_cert_list.dump(), self._hash_algo)

        return crl.CertificateList({
            'tbs_cert_list': tbs_cert_list,
            'signature_algorithm': {
                'algorithm': signature_algorithm_id
            },
            'signature': signature
        })


def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:

     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace

    :param string:
        The string to format

    :param *params:
        Params to interpolate into the string

    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output


def _type_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)
