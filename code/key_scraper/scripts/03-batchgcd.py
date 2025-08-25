import os
import sys
import io
import logging
import csv
import json
from collections import defaultdict
tool_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../rsa_factorability_tool/"))
sys.path.append(tool_path)
from tool import FactorabilityTool
from tool.data import ElasticSearchCrawler
from tool.data import Database
from tool.rsa import Analyzer
from config import *
from bson.objectid import ObjectId


if __name__ == "__main__":
    config = FactorabilityTool.read_config()
    #config["mongodb"]["password"] = str(os.getenv("MONGO_PW"))
    config["mongodb"]["password"] = "mongopw"
    config["mongodb"]["username"] = "mongo"
    config["mongodb"]["tls"] = "false"
    config["elastic"]["username"] = "elastic"
    config["elastic"]["password"] = "elasticsearchpass"
    config["elastic"]["index"] = INDEX_KEYS_UNIQUE

    ElasticSearchCrawler.start(config, None)

    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    logger = Analyzer.logger
    lvl = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    try:
        pass
        Analyzer.analyze_factorability(config)  
        Analyzer.primefactor_analysis(config, "code/rsa_factorability_tool/primes.output")
    finally:
        logger.removeHandler(handler)
    logger.setLevel(lvl)


    # Get log contents
    result_log = log_stream.getvalue()
    results = defaultdict(list)


    for x in result_log.splitlines():
        parts = x.split(" ")
        mongo_id = parts[0]
        if "showed GCD" in x:
            results[mongo_id].append({"check": "batch_gcd", "fatal": True, "info": f"Found GCD {parts[-1]}"})
        if "showed primefactors of" in x:
            primefacs = x.split("[")[1][:-1]
            results[mongo_id].append({"check": "small_primefactor", "fatal": True, "info": f"Found Small Primefactors {primefacs}"})


    mongo_database = Database.Database(config)
    db = mongo_database.database
    rows_to_add = []
    
    for k,v in results.items():
        for cert in db.certs.find({"key": ObjectId(k)}):
            add_info = cert.get("add_info")
            user = add_info.get("user")
            metadata = add_info.get("metadata")
            elastic_index = metadata.get("elastic_index")
            elastic_id = metadata.get("elastic_id")
            fpr = metadata.get("fpr")
            rows_to_add.append([elastic_index, elastic_id, "rsa", fpr, json.dumps(user), {"compromised": False, "issues": v}])

    mongo_database.db_client.close()

    RESULTS_FILE_IN = f"{RESULTS_DIR}/03-analysis-results.csv"
    RESULTS_FILE_OUT = f"{RESULTS_DIR}/03-analysis-results-with-gcd.csv"
    with open(RESULTS_FILE_IN, 'r') as infile, open(RESULTS_FILE_OUT, "w") as out:
        reader = csv.reader(infile)
        writer = csv.writer(out)
        for row in reader:
            for to_add in rows_to_add[:]:
                if to_add[1] == row[1] and to_add[3] == row[3]:
                    print(row, to_add)
                    print()
                    findings = json.loads(row[5])
                    findings["issues"].extend(to_add[5]["issues"])
                    row[5] = json.dumps(findings)
                    rows_to_add.remove(to_add)
            writer.writerow(row)
        for row in rows_to_add:
            row[5] = json.dumps(row[5])
        writer.writerows(rows_to_add)
            

