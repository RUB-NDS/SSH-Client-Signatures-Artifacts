from tool.rsa.Finder import Finder
from badkeys.checks import checkrsa
from badkeys.checks import checkcrt
from badkeys.checks import checksshpubkey
from badkeys.checks import detectandcheck
from badkeys.scantls import scantls
from badkeys.scanssh import scanssh


# calls different projects and merges their results into a single dictionary


class ResultMerger:


    @staticmethod
    def scan(key: str, finder: Finder):
        # list of error description in the submodules
        results = {}
        bad_key = False

        results['gcd_database'], b1 = ResultMerger.get_gcd_database_results(finder, key)
        results['bad_keys'], b2 = ResultMerger.get_bad_keys_resuls(key)

        bad_key |= (b1 | b2)

        results['bad_key'] = bad_key

        return results


    @staticmethod
    def get_gcd_database_results(finder: Finder, key: str):
        # bachelor thesis stuff
        batch_gcd_results = {}
        bad_key = False

        # returns a list of shared prime moduli
        try:
            primes = finder.get_shared_factors(key)
        except Exception as e:
            batch_gcd_results['error'] = str(e)
        else:
            if primes is not None and len(primes) > 0:
                factorizable = True
            else:
                factorizable = False
            batch_gcd_results['factorizable'] = factorizable
            batch_gcd_results['factor'] = str(primes)
            bad_key = factorizable
        return batch_gcd_results, bad_key


    @staticmethod
    def get_bad_keys_resuls(key):
        # badkeys stuff:
        bad_key_results = {}
        bad_key = False

        bad_key_results['url_results'], b1 = ResultMerger.get_url_results(key)
        bad_key_results['int_results'], b2 = ResultMerger.get_int_results(key)
        bad_key_results['crt_results'], b3 = ResultMerger.get_crt_results(key)
        bad_key_results['ssh_pub_key_results'], b4 = ResultMerger.get_ssh_pub_key_results(key)
        bad_key_results['other_key'], b5 = ResultMerger.get_other_key(key)

        bad_key |= (b1 | b2 | b3 | b4 | b5)

        return bad_key_results, bad_key


    @staticmethod
    def get_url_results(key):
        # parse as url
        url_results = {}
        bad_key = False

        url_results['tls_results'], b1 = ResultMerger.get_tls_results(key)
        url_results['ssh_results'], b2 = ResultMerger.get_ssh_results(key)

        # forward bad_key results from calls
        bad_key |= (b1 | b2)
        return url_results, bad_key


    @staticmethod
    def get_tls_results(key):
        # check tls port
        tls_results = {}
        bad_key = False

        try:
            # try splitting into host and port, simply discard errors
            host, port = key.split(':')
            result = scantls(host, port)[0]['results']
        except Exception as e:
            tls_results['error'] = str(e)

        else:
            if result == {}:
                tls_results['error'] = 'Not vulnerable'
            else:
                tls_results['res'] = result
                bad_key = True
        return tls_results, bad_key

    @staticmethod
    def get_ssh_results(key):
        # check ssh port
        ssh_results = {}
        bad_key = False

        try:
            # try splitting into host and port, simply discard errors
            host, port = key.split(':')
            result = scanssh(host, port)
        except Exception as e:
            ssh_results['error'] = str(e)
        else:
            if result == []:
                ssh_results['error'] = 'Not vulnerable'
            else:
                ssh_results['res'] = result
                bad_key = True
        return ssh_results, bad_key

    @staticmethod
    def get_int_results(key):
        # parse as number
        number_results = {}

        # try base 10
        try:
            n = int(key)
            result = checkrsa(n)
        except Exception as e:
            number_results['error'] = str(e)
        else:
            number_results['res'] = result
            return number_results, True

        # try base 16
        try:
            n = int(key, 16)
            result = checkrsa(n)
        except Exception as e:
            number_results['error'] = str(e)
            return number_results, False
        else:
            number_results.pop('error', None)
            number_results['res'] = result
            return number_results, True


    @staticmethod
    def get_crt_results(key):
        # parse as certificate
        certificate_results = {}
        bad_key = False

        try:
            result = checkcrt(key)
            if len(result['results'].keys()) == 0:
                certificate_results['error'] = result['type']
            else:
                certificate_results['res'] = result
                bad_key = True
        except Exception as e:
            certificate_results['error'] = str(e)
        return certificate_results, bad_key


    @staticmethod
    def get_ssh_pub_key_results(key):
        # parse as certificate
        ssh_pub_key_results = {}
        bad_key = False

        try:
            result = checksshpubkey(key)
            if len(result['results'].keys()) == 0:
                ssh_pub_key_results['error'] = result['type']
            else:
                ssh_pub_key_results['res'] = result
                bad_key = True
        except Exception as e:
            ssh_pub_key_results['error'] = str(e)
        return ssh_pub_key_results, bad_key


    @staticmethod
    def get_other_key(key):
        # parse as certificate
        other_key = {}
        bad_key = False

        try:
            result = detectandcheck(key)
            if len(result['results'].keys()) == 0:
                other_key['error'] = result['type']
            else:
                other_key['res'] = result
                bad_key = True
        except Exception as e:
            other_key['error'] = str(e)
        return other_key, bad_key

