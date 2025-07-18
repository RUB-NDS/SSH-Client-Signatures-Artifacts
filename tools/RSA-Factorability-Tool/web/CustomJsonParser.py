import json
from gmpy2 import mpz

class CustomJsonParser(json.JSONEncoder):
    def default(self, object):
        if isinstance(object, mpz):
            return object.digits(10)
        return json.JSONEncoder.default(self, object)
