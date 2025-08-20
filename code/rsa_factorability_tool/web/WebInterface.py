from flask import Flask, request, render_template, jsonify
from waitress import serve

from tool.data.Database import Database
from tool.data.SingleKeyAdder import SingleCertAdder
from tool.rsa.Finder import Finder
from web.CustomJsonParser import CustomJsonParser
from web.ResultMerger import ResultMerger

app = Flask(__name__)
app.json_encoder = CustomJsonParser


# TODO: replace with session when adding login features
class DataStore:
    config = None
    finder = None
    singleCertAdder = None
    Database = None


data = DataStore()


@app.route("/")
def mainpage():
    return render_template("webinterface.html"), 200


def run(config):
    data.config = config
    data.Database = Database(config)
    data.finder = Finder(config)
    data.singleCertAdder = SingleCertAdder(config)
    serve(app, host=config["flask"]["host"], port=config["flask"]["port"])
    # app.run(host=config["flask"]["host"], port=config["flask"]["port"])
    data.finder.finish()


### API ###
@app.route("/stats", methods=['GET'])
def stats():
    amtKeys = data.finder.db.database.keys.count_documents({})
    amtCerts = data.finder.db.database.certs.count_documents({})
    amtOccs = data.finder.db.database.occurrences.count_documents({})
    return success({'keys': amtKeys,
                    'certificates': amtCerts,
                    'occurrences': amtOccs})


@app.route('/rsa_cert', methods=['GET'])
def rsa_cert():
    try:
        cert = request.args.get("find")
    except KeyError:
        return error("Invalid Parameter")
    if cert is None or cert == "":
        return error("Invalid Parameter")
    try:
        # merge all dictionaries
        findings = ResultMerger.scan(cert, data.finder)
    except Exception as e:
        return error(str(e))
    return success(findings)


@app.route('/add_rsa_cert', methods=['POST'])
def add_rsa_cert():
    try:
        cert = request.form['add']
    except:
        return error("Invalid Content Type")
    if cert is None or cert == "":
        return error("Invalid Parameter")
    try:
        data.singleCertAdder.add_input_to_database(cert)
        return success({'information': 'key successfully added to database'})
    except Exception as e:
        return error(str(e))


def error(description: str):
    return jsonify({'status': 400,
                    'description': description})


def success(data: dict):
    return jsonify({'status': 200,
                    'data': data})
