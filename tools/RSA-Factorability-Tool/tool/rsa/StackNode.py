class StackNode:
    def __init__(self, height, N, db_id):
        self.height = height
        self.N = N
        self.db_id = db_id

    def __str__(self):
        return "\n\tStackNode height=" + str(self.height) + "; N=...; db_id=" + str(self.db_id)
