from gmpy2 import *
from pymongo import *
from typing import List

from tool.data.Database import Database
from tool.parsing.Parser import Parser
from tool.rsa.KeyTreeNode import KeyTreeNode


class Finder:

    def __init__(self, config):
        self.db = Database(config)

    def acquire_root_nodes(self) -> List[KeyTreeNode]:
        """
        Loads the root nodes of the key trees from the database
        :return: list[KeyTreeNode] of root nodes
        """
        print("Loading root nodes...")
        root_nodes = []
        keytree_collection_list = self.db.database.list_collection_names(filter={"name": {"$regex": r"^keytree"}})
        for coll_name in keytree_collection_list:
            coll = self.db.database[coll_name]
            root_node_db = coll.find_one(sort=[("h", DESCENDING)])
            if root_node_db is None:
                continue
            N = from_binary(root_node_db.get("N"))
            root_node = KeyTreeNode(root_node_db.get("h"), N, coll, root_node_db.get("_id"))
            root_nodes.append(root_node)
        return root_nodes

    def recurse_tree(self, node, key):
        """
        Performs a binary search for the given key
        :param node: KeyTreeNode to recursively perform the search on
        :param key: The key's modulus to search factorable keys with
        :return: list of found keys the key is factorable
        """
        g = gcd(node.N, key)
        if node.height == 0:
            # key in database
            if g == key:
                return [g]
            if g > 1:
                print("Key is factorable with key", node.db_id, "and gcd of", g)
                # TODO: remove the printing of factor later
                # return [node.db_id, ]
                return [g]
            return []
        # TODO: seems to be unnecessary
        # if g == key:
            # g = gcd(divexact(node.N, key), key)
        if g > 1:
            children = self.db.get_children(node)
            result = []
            result.extend(self.recurse_tree(children[0], key))
            result.extend(self.recurse_tree(children[1], key))
            return result
        return []

    def get_shared_factors(self, key):
        """
        Starts the recursive search for the given key/modulus/N to check if the key is factorizable in any KeyTree
        :param key: The key's modulus to search factorable keys with
        :return: The combined results of all findings in all trees
        """
        root_nodes = self.acquire_root_nodes()
        # parse arbitrary key input into mpz number
        key = Parser.get_rsa_key_from_input(key, self.db)
        result = []
        for root_node in root_nodes:
            result.extend(self.recurse_tree(root_node, key))
        # pretty result
        _result = []
        for p in result:
            q = divexact(key, p)
            _result.extend([(q.digits(10), p.digits(10))])
        return _result

    def finish(self):
        self.db.finish()


if __name__ == "__main__":
    print("Usage: python3 FactorabilityTool.py --help")
