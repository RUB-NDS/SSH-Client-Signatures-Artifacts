import argparse
import logging
import os
import sys
from configparser import ConfigParser
from datetime import datetime

from tool.data.SingleKeyAdder import SingleCertAdder
from tool.data import ElasticSearchCrawler
from tool.rsa import Analyzer
from tool.rsa.Finder import Finder

def read_config():
    """
    Reads the config file or creates it with defaults if it doesn't exist
    """
    config_file_name = "factorabilitytool.conf"
    config = ConfigParser()
    if os.path.isfile(config_file_name):
        config.read(config_file_name)
        return config
    else:
        config["mongodb"] = {
            "host": "localhost",
            "port": "27017",
            "db_name": "factorability",
            "username": "",
            "password": "",
            "tls": "true",
            "allowInvalidCertificates": "false",
        }
        config["flask"] = {
            "host": "0.0.0.0",
            "port": "5000",
        }
        config["elastic"] = {
            "host": "localhost",
            "port": "9200",
            "username": "",
            "password": ""
        }
        with open(config_file_name, "w") as cfgfile:
            config.write(cfgfile)
        return config

def prepare_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    es_logger = logging.getLogger("elastic_transport.transport")
    es_logger.setLevel(logging.WARNING)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.ERROR)

    file_handler = logging.FileHandler(f'{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')
    file_handler.setLevel(logging.DEBUG)

    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)

def run_using_args():
    """
    Parse arguments and run the program accordingly
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--finder", metavar="key", type=str, nargs='+',
                        help="Find duplicate or factorable keys given a "
                             "database id, RSA public key")
    parser.add_argument('--reuse-analysis', action='store_true', help="Run reused key analysis")
    parser.add_argument('--fac-analysis', action='store_true', help="Run factorable key analysis")
    parser.add_argument("-o", '--out', metavar="out-dir", type=str, help="Directory to output analysis results to")
    parser.add_argument("-a", "--add", metavar="key", type=str, nargs='+',
                        help="Add a RSA public key to the database")
    parser.add_argument('--elasticsearch_crawl', action='store_true', help="ElasticSearch")
    parser.add_argument("--find-primefactors", metavar="primesfile", type=str, help="")
    args = parser.parse_args()

    config = read_config()

    if args.add is not None:
        singleAdder = SingleCertAdder(config)
        for x in args.add:
            singleAdder.add_input_to_database(x)
        return

    # analyse complete database on key reuse
    if args.reuse_analysis:
        if args.out is None or args.out == "":
            print("No out dir specified")
            exit(-1)
        Analyzer.reuse_cert_analysis(config, args.out)
        return

    # analyse complete database on key factorability
    if args.fac_analysis:
        Analyzer.analyze_factorability(config)
        return


    # read certificates from rapid 7 lists
    if args.elasticsearch_crawl:
        ElasticSearchCrawler.start(config, args)
        return

    if args.find_primefactors is not None and args.find_primefactors != "":
        Analyzer.primefactor_analysis(config, args.find_primefactors)

    # check if single key is being reused or factorable
    if args.finder is not None:
        finder = Finder(config)
        for x in args.finder:
            finder.get_shared_factors(x)
        finder.finish()
        return

if __name__ == '__main__':
    prepare_logger()
    read_config()
    run_using_args()
