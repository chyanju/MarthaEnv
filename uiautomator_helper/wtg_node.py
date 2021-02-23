import copy


class WTGNode:
    def __init__(self, node_key, node_value):
        self.node_value = node_value
        self.node_key = node_key
        self.available_actions = []
        self.node_state = None
        self.node_id = None
        self.node_type = None
        self.setup()

    def setup(self):
        self.node_type = self.node_value.split("[")[0]
        self.node_id = self.node_value.split("[")[1].split("]")[1]
        self.node_state = self.node_value.split("[")[1].split("]")[0]

    def __str__(self):
        pass