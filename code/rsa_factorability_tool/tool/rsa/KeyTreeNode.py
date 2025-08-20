class KeyTreeNode:
    def __init__(self, height, N, collection, db_id):
        self.height = height
        self.N = N
        self.collection = collection
        self.db_id = db_id

    def __str__(self):
        return "\n\tKeyTreeNode height=" + str(self.height) + "; N=...; db_id=" + str(self.db_id) + " in collection="+str(self.collection)