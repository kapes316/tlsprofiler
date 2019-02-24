import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import binascii


class certificate_decode:
    @staticmethod
    def keyAlgorithmName(key):
        class_name = key.__class__.__name__
        if class_name == "_RSAPublicKey" : return "RSA"
        if class_name == "_DSAPublicKey": return "DSA"
        if class_name == "_EllipticCurvePublicKey": return "EllipticCurve"
        return "UNKNOWN"

    @staticmethod
    def decode_certificate(cert_in):
        pem = ""

        for i in cert_in:
            pem = pem + str(i) + "\n"
        data = {}
        cert = x509.load_pem_x509_certificate(bytes(pem,"utf8"), default_backend())
        data["SHA256"] = binascii.hexlify(cert.fingerprint(hashes.SHA256()));
        x = cert.fingerprint(hashes.SHA256())
        data["subject"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value
        data["issuer"] = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0]._value
        data["signatureAlgorithm"] = cert.signature_algorithm_oid._name
        data["keyAlgorithm"] = certificate_decode.keyAlgorithmName(cert.public_key())
        data["keySize"] = cert.public_key().key_size
        data["serialNumber"] = str(cert.serial_number)
        data["notValidBefore"] = cert.not_valid_before.ctime()
        data["notValidAfter"] = cert.not_valid_after.ctime()
        data["dateFirstSeen"] =  datetime.datetime.utcnow()
        return data