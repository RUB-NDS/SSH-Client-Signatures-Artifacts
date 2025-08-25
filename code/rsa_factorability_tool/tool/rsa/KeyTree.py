from time import time

from pymongo import *
from gmpy2 import *

from tool.rsa.StackNode import StackNode


class KeyTree:
    def __init__(self, db, keytree_num):
        self.database = db
        self.stack = []
        self.keytree = self.database["keytree" + str(keytree_num)]
        self.keytree.create_index("h")
        self.keytree_num = keytree_num
        self.restore_stack()
        self.tree_full = False
        self.start = time()

    def reduce(self, ignore_size=False):
        """
        Reduces the stack by popping the two top nodes, creating a new node with that two nodes as children and putting it
        on top of the stack. This is iteratively repeated.

        If ignore_size is False, the two top nodes have to have the same tree height. The iteration stops, if the two top
        nodes have different sizes. This is used during tree building.

        If ignore_size is True, the iteration stops if only one node is left. This is used when adding new nodes is finished
        and the tree is completed to be stored.

        :returns True if the tree is full and a new tree needs to be used
        """
        while len(self.stack) >= 2 and (ignore_size or self.stack[-1].height == self.stack[-2].height):
            right_el = self.stack.pop()
            left_el = self.stack.pop()
            N = left_el.N * right_el.N
            new_id = self.keytree.insert_one(
                {"N": to_binary(N), "lc": left_el.db_id, "rc": right_el.db_id, "h": left_el.height + 1}).inserted_id
            self.stack.append(StackNode(left_el.height + 1, N, new_id))
            if not ignore_size and left_el.height + 1 == 15:
                #print("Maximum tree size reached")
                #print("Stack", *self.stack)
                #print("Took", (time()-self.start))
                self.tree_full = True

    def restore_stack(self):
        """
        Load the tree from the database, remove nodes that have been added to complete the tree and restore the stack to
        continue adding new nodes to the tree.
        """
        zero_node = self.keytree.find_one({"h": 0})
        # base case only one key present
        if zero_node is not None:
            self.stack = [StackNode(0, from_binary(zero_node.get("N")), zero_node.get("child"))]
            self.keytree.delete_one({"_id": zero_node.get("_id")})
            return
        path = []
        # get root node
        current_node = self.keytree.find_one(sort=[("h", DESCENDING)])
        # base case no key at all
        if current_node is None:
            #print("Tree empty, nothing to do")
            return
        # add all right children into
        while current_node is not None:
            path.append(current_node)
            current_node = self.keytree.find_one({"_id": current_node.get("rc")})

        path.reverse()
        # Find lowest node, where left and right subtree are unequally high and remove that
        i = 0
        if len(path) > 0:
            try:
                while path[i].get("h") == i + 1:
                    i += 1
            except:
                # tree is balanced, so append root_node
                root_node = path[-1]
                self.stack.append(
                StackNode(root_node.get("h"), from_binary(root_node.get("N")),
                          root_node.get("_id")))
                return

        if i > 0:
            right_child_of_split_node = path[i - 1]
            self.stack.append(
                StackNode(right_child_of_split_node.get("h"), from_binary(right_child_of_split_node.get("N")),
                          right_child_of_split_node.get("_id")))

            left_child_of_split_node = self.keytree.find_one({"_id": path[i].get("lc")})
            self.stack.append(
                StackNode(left_child_of_split_node.get("h"), from_binary(left_child_of_split_node.get("N")),
                          left_child_of_split_node.get("_id")))
            self.keytree.delete_one({"_id": path[i].get("_id")})

            path = path[(i + 1):]
        else:
            leave = self.database.keys.find_one({"_id": path[0].get("rc")})
            self.stack.append(StackNode(0, from_binary(leave.get("N")), path[0].get("rc")))

        for node in path:
            left_child = self.keytree.find_one({"_id": node.get("lc")})
            self.stack.append(StackNode(left_child.get("h"), from_binary(left_child.get("N")), left_child.get("_id")))

        self.stack.reverse()

        self.keytree.delete_one({"_id": {"$in": [x.get("_id") for x in path]}})
        #print("RestoredStack:", *self.stack)

    def flush_stack(self):
        """
        Reduces the stack and stores the remaining node to completely store the tree
        """
        self.reduce(ignore_size=True)
        assert len(self.stack) <= 1
        endNode = self.stack[0]
        if endNode.height == 0:
            self.keytree.insert_one({"N": to_binary(endNode.N), "child": endNode.db_id, "h": 0})

    def add_to_tree(self, N, key_id):
        """
        Add a new node to the tree
        :param N: Modulus product of the subtree of that node
        :param key_id: ID of the key if node is a leaf
        :raises: Exception if the tree is full
        """
        if self.tree_full:
            raise Exception("Keytree is full")
        self.stack.append(StackNode(0, N, key_id))
        self.reduce()
