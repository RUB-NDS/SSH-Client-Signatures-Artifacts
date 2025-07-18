import random

from tool.data.Database import Database
from tool.parsing.Parser import Parser


class SingleCertAdder:

    def __init__(self, config):
        self.db = Database(config)

    def add_rsa_cert_to_database(self, cert):
        exception = None
        n, additional_info, fingerprint = Parser.get_rsa_key_and_additional_info_from_pem_cert(cert, "SingleCert")
        self.db.start_insert()
        try:
            kid = self.db.add_ssh_key(n, fingerprint, additional_info, None)
            self.db.add_ssh_key_occurrence(fingerprint, '127.0.0.1', '0000', kid)
        except Exception as e:
            exception = e
        finally:
            self.db.stop_insert()
        if exception is not None:
            raise exception

    def add_rsa_key_to_database(self, key):
        exception = None
        fingerprint = ''.join(random.choice('0123456789ABCDEF') for _ in range(40))
        additional_info = {"type": "pure modulus"}
        self.db.start_insert()
        try:
            self.db.add_ssh_key(key, fingerprint, additional_info, None)
        except Exception as e:
            exception = e
        finally:
            self.db.stop_insert()
        if exception is not None:
            raise exception

    def add_input_to_database(self, key):
        cert = Parser.get_rsa_key_from_input(key, None)
        return self.add_rsa_key_to_database(cert)
