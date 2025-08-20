import random
import ssl
from base64 import b64decode

from bson import ObjectId
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from gmpy2 import *

from tool.data.Database import Database

from tool.parsing.ParsingException import ParsingException


class Parser:
    """
    Holds functions for parsing between certificates, rsa moduli, etc.
    """

    @staticmethod
    def get_rsa_key_from_db_id(db_id, db: Database):
        """
        Loads key modulus from the database
        :param db_id: Database of the key
        :param db: the database to search
        :return: Search Result
        """
        print("Analysing key with database id", db_id)
        key = db.database.keys.find_one({"_id": ObjectId(db_id)})
        if key is None:
            raise ParsingException("Key with id", db_id, "not found in database.")
        from_binary(key.get("N"))

    @staticmethod
    def get_rsa_key_from_pem_cert(cert):
        """
        Extracts the public key's modulus from the certificate
        :param cert: Certificate PEM String (without ----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
        :return: Search Result
        """
        certDer = b64decode(cert)
        cert = x509.load_der_x509_certificate(certDer, default_backend())
        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ParsingException("Certificate does not contain an RSA key")
        print("Analyzing key from certificate")
        N = public_key.public_numbers().n
        return mpz(N)

    @staticmethod
    def get_rsa_key_and_additional_info_from_pem_cert(cert, additional_info_type):
        """
        Extracts the public key's modulus and additional info from the certificate
        :param cert: Certificate PEM String (without ----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
        :param additional_info_type: Type info for additional data (e.g. sonarssl)
        :return: key modulus, additional info, and new id number
        """
        cert = x509.load_der_x509_certificate(cert, default_backend())
        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ParsingException("Not an RSA Key!")

        n = public_key.public_numbers().n
        fingerprint = ''.join(random.choice('0123456789ABCDEF') for _ in range(40))
        try:
            additional_info = {"type": additional_info_type,
                               "Subject": cert.subject.rfc4514_string(),
                               # TODO: This seems to be part of the Rapid7 SonarSSL certificate lists, we can generate those ourselves
                               # "file_id": str(cert_line[:40]),
                               "Issuer": cert.issuer.rfc4514_string(),
                               "nvb": cert.not_valid_before,
                               "nva": cert.not_valid_after,
                               "sn": str(cert.serial_number)}
        except Exception as e:
            additional_info = {"type": additional_info_type, "Error": str(e), "file_id": fingerprint}

        return n, additional_info, fingerprint, None

    @staticmethod
    def get_rsa_key_from_ssh_key(key):
        loaded_key = serialization.load_ssh_public_key(str.encode(key))
        if not isinstance(loaded_key, rsa.RSAPublicKey):
            raise ParsingException("Not an RSA Key!")
        n = loaded_key.public_numbers().n
        return mpz(n)


    @staticmethod
    def get_rsa_key_from_input(key, db=None):
        """
        Decides which find function needs to be used based on the given input format
        :param key: Certificate in PEM format, Key modulus or database id
        :param db: Database to search for if the key is given as a database id
        :return: Search Result
        """
        #if type(key) == Namespace:

        # database id
        if len(key) == 24:
            if db is None:
                raise Exception
            return Parser.get_rsa_key_from_db_id(key, db)
        # X509 certificate without wrapping strings
        elif key.startswith("M"):
            return Parser.get_rsa_key_from_pem_cert(key)
        # X509 certificate
        elif key.startswith("-----BEGIN CERTIFICATE-----"):
            return Parser.get_rsa_key_from_pem_cert(key[28:-26])
        # IP/Port to fetch from server
        elif key.startswith("ssh-rsa"):
            return Parser.get_rsa_key_from_ssh_key(key)
        else:
            return mpz(key)
