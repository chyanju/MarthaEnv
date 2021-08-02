import networkx
from statements import *
from utils import *
from hierarchy import NoConcreteDispatch
from bbnode import *
#import IPython
from collections import defaultdict



class CFG:
    """
        Build function CFGs
    """

    def __init__(self, method, graph_dir):
        self.method = method
        self.method_callees = defaultdict(list)
        self.graph_dir = graph_dir
        self.irblock_to_basicblock = {}
        self.function_cfg = networkx.MultiDiGraph()
        #self.get_basic_block_nodes()
        self.build_cfg()

    def get_basic_block_nodes(self):

        for block in self.method.blocks:
            basic_block = BBNode(block)
            self.irblock_to_basicblock[block] = basic_block
    
    def build_cfg(self):
        blocks_dict = self.method.basic_cfg
        name = None
        worklist = []
        worklist.append(self.method.blocks[0])
        
        visited_blocks = []

        while len(worklist) != 0:
            block = worklist.pop(0)

            if block not in self.irblock_to_basicblock.keys():
                basic_block = BBNode(block)
                self.irblock_to_basicblock[block] = basic_block
            
            if block in blocks_dict.keys() and block not in visited_blocks:
                visited_blocks.append(block)
                stmt_type = ''

                src_basic_block = self.irblock_to_basicblock[block]
                if not self.function_cfg.has_node(src_basic_block):
                    self.function_cfg.add_node(src_basic_block)
                
                child_prob = src_basic_block._bb_prob/len(blocks_dict[block])
                last_statement = block.statements[-1]

                if type(last_statement).__name__ == 'IfStmt':
                    cond_expr = last_statement.condition
                    target_block_label = last_statement.target
                    src_basic_block._condition = cond_expr
                    stmt_type = 'if'
                
                if type(last_statement).__name__ == 'LookupSwitchStmt':
                    switch_key = last_statement.key
                    targets = last_statement.lookup_values_and_targets
                    src_basic_block._switch_key = switch_key

                    target_to_value = {}
                    
                    for target in targets.keys():
                        target_to_value[targets[target]] = target
                    
                    target_to_value[last_statement.default_target] = 'default'
                    stmt_type = 'sw'
                
                for child_block in blocks_dict[block]:
                    worklist.append(child_block)
                    
                    if child_block not in self.irblock_to_basicblock.keys():
                        basic_block = BBNode(child_block)
                        self.irblock_to_basicblock[child_block] = basic_block
                    
                    child_basic_block = self.irblock_to_basicblock[child_block]
                    
                    if self.function_cfg.has_node(child_basic_block):
                        if not networkx.has_path(self.function_cfg, child_basic_block, src_basic_block):
                            child_basic_block._bb_prob += child_prob
                        else:
                            name = self.method
                        
                    else:
                        child_basic_block._bb_prob = child_prob

                    if stmt_type == 'if':
                        if target_block_label == child_basic_block._basic_block_ref.label:
                            self.function_cfg.add_edge(src_basic_block, child_basic_block, key='True', weight=child_basic_block._bb_prob)
                        else:
                            self.function_cfg.add_edge(src_basic_block, child_basic_block, key='False', weight=child_basic_block._bb_prob)
                    
                    elif stmt_type == 'sw':
                        value = target_to_value[child_basic_block._basic_block_ref.label]
                        self.function_cfg.add_edge(src_basic_block, child_basic_block, key=value, weight=child_basic_block._bb_prob)
                    
                    else:
                        self.function_cfg.add_edge(src_basic_block, child_basic_block, key='None', weight=child_basic_block._bb_prob)

        #if name != None:
            #IPython.embed()    


