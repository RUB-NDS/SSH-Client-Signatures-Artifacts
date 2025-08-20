from bson import ObjectId
from gmpy2 import to_binary, mpz, from_binary
from pymongo import *

from tool.rsa.KeyTree import KeyTree
from tool.rsa.KeyTreeNode import KeyTreeNode


class Database:

    def __init__(self, config):
        host = config["mongodb"]["host"]
        port = config["mongodb"]["port"]
        username = config["mongodb"]["username"]
        password = config["mongodb"]["password"]
        tls = config["mongodb"]["tls"]
        insecure = config["mongodb"]["allowInvalidCertificates"]
        tls_str = f"?tls={tls}"
        if tls == "true":
            tls_str += f"& tlsAllowInvalidCertificates={insecure}"
        self.db_client = MongoClient(f'mongodb://{username}:{password}@{host}:{port}/{tls_str}')
        self.database = self.db_client[config["mongodb"]["db_name"]]
        self.keytree = None
        self.insert_mode = False
        self.database.keys.create_index("ni")
        self.database.certs.create_index("fi_index")
        self.database.occurrences.create_index("cert")

    def add_ssh_key(self, N, key_fingerprint: (str | bytes | int), key_info: dict, occurrence_info: set):
        """
        Adds a key to the database. Key and modulus wont be added if they already exist.

        :param N: Modulus of the key
        :param key_fingerprint: key fingerprint to use for identification within the database
        :param key_info: additional info to store for the key
        :param occurrence_info: occurrence info (ip and port, etc.) to store with the key
        """

        # add a few sanity checks (for example adding a zero breaks everything)

        if N <= 6:
            raise ArithmeticError("RSA keys must be larger than 6")

        assert self.insert_mode
        db = self.database

        if type(key_fingerprint) is str:
            key_fingerprint_index = int.from_bytes(key_fingerprint.encode()[-4:], "big")
        elif type(key_fingerprint) is bytes:
            key_fingerprint_index = int.from_bytes(key_fingerprint[-4:], "big")
        else:
            key_fingerprint_index = key_fingerprint

        N = mpz(N)
        ni = N % (2 ** 32)
        ni = int(ni)
        binary_N = to_binary(N)

        key_from_db_id = db.certs.find_one(
            {"fi_index": key_fingerprint_index, "fingerprint": key_fingerprint})

        exists = db.keys.find_one({"ni": ni, "N": binary_N})

        if key_from_db_id is None:
            if exists is None:
                key_id = db.keys.insert_one({"N": binary_N, "ni": ni}).inserted_id
                if self.keytree.tree_full:
                    self.keytree = KeyTree(self.database, self.keytree.keytree_num + 1)
                self.keytree.add_to_tree(N, key_id)
            else:
                key_id = exists.get("_id")
            db_key_id = db.certs.insert_one(
                {"fi_index": key_fingerprint_index, "fingerprint": key_fingerprint,
                 "add_info": key_info,
                 "key": key_id}).inserted_id
        else:
            #TODO REVERT CORRECT CERT ID HERE
            db_key_id = 0
        if occurrence_info is not None:
            db_key_id = key_from_db_id.get("_id")
            occurrence_info.update({"cert": db_key_id})
            db.occurrences.insert_one(occurrence_info)
        return db_key_id

    def add_ssh_key_occurrence(self, key_fingerprint, ip: str, port: str, key_id: ObjectId):
        """
        Adds occurrences to existing key

        :param key_fingerprint: fingerprint used for identification
        :param ip: ip address to associate with key
        :param port: port to associate with key
        :param key_id: optional: if known, the database id
        :return:
        """
        db = self.database
        if key_id is None:
            key_fingerprint_index = int.from_bytes(key_fingerprint.encode()[-4:], "big")
            key_from_db = db.certs.find_one(
                {"fi_index": key_fingerprint_index, "fingerprint": key_fingerprint})
            if key_from_db is None:
                return
            else:
                key_id = key_from_db.get("_id")
        db.occurrences.insert_one({"ip": ip, "port": port, "cert": key_id})

    def init_keytree(self, next=False):
        """
        Load the newest key tree from the database, or a new one if specified or none exists.

        :param next: start a new keytree
        """
        keytree_collection_list = self.database.list_collection_names(filter={"name": {"$regex": r"^keytree"}})
        num = 0
        if len(keytree_collection_list) > 0:
            num = max([int(x[7:]) for x in keytree_collection_list])
        if next:
            num += 1
        self.keytree = KeyTree(self.database, num)
        self.insert_mode = True

    def start_insert(self):
        """
        Starts database insert mode
        """
        assert not self.insert_mode
        self.init_keytree()

    def stop_insert(self):
        """
        Stops database insert mode and stores the current key tree
        """
        assert self.insert_mode
        print("Stack before exit:", *self.keytree.stack)
        self.keytree.flush_stack()
        self.insert_mode = False

    def get_children(self, keytreenode : KeyTreeNode) -> (KeyTreeNode, KeyTreeNode):
        """
        Get the children of a key tree node

        :param keytreenode: the key tree node to get the children for
        :return: Tupel containing the children
        """
        assert keytreenode.height > 0
        keytree = keytreenode.collection
        node = keytree.find_one({"_id": keytreenode.db_id})
        assert node is not None
        if node.get("h") == 1:
            left_child_node = self.database.keys.find_one({"_id": node.get("lc")})
            right_child_node = self.database.keys.find_one({"_id": node.get("rc")})
            left_child = KeyTreeNode(0, from_binary(left_child_node.get("N")), keytree, node.get("lc"))
            right_child = KeyTreeNode(0, from_binary(right_child_node.get("N")), keytree, node.get("rc"))
        else:
            left_child_node = keytree.find_one({"_id": node.get("lc")})
            right_child_node = keytree.find_one({"_id": node.get("rc")})
            left_child = KeyTreeNode(left_child_node.get("h"), from_binary(left_child_node.get("N")), keytree,
                                     node.get("lc"))
            if right_child_node is None:
                right_child_node = self.database.keys.find_one({"_id": node.get("rc")})
                right_child = KeyTreeNode(0, from_binary(right_child_node.get("N")), keytree, node.get("rc"))
            else:
                right_child = KeyTreeNode(right_child_node.get("h"), from_binary(right_child_node.get("N")), keytree,
                                          node.get("rc"))
        return left_child, right_child

    def finish(self):
        """
        Stops insert mode and closes database connection
        """

        if self.insert_mode:
            self.stop_insert()
        self.db_client.close()
