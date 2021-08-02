class BBNode:
    bb_id = 0
    
    def __init__(self, block_ref):
        self._basic_block_ref = block_ref
        self._condition_expr = None
        self._switch_key = None
        self._bb_prob = 1
        BBNode.bb_id += 1
        self._bb_id = BBNode.bb_id

    def __str__(self):
        label = '"BBID: %d\n' % self._bb_id + "\n" + "Block probability: " + str(self._bb_prob) + '"'
        return label

    # Ref: https://stackoverflow.com/a/15774013
    def __deepcopy__(self, memo):
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            if k != '_basic_block_ref' and k != 'bb_id' and k != '_bb_id' and k!= '_condition_expr' and k!= '_switch_key':
                setattr(result, k, deepcopy(v, memo))
        
        BBNode.bb_id += 1
        setattr(result, '_bb_id', BBNode.bb_id)        
        setattr(result, '_basic_block_ref', self._basic_block_ref)
        setattr(result, '_condition_expr', self._condition_expr)
        setattr(result, '_switch_key', self._switch_key)
        return result