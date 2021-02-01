import networkx
from statements import *
from utils import *
from hierarchy import NoConcreteDispatch
from bbnode import *
#import IPython
from collections import defaultdict



class ICFG:
    """
        Build ICFGs
    """
    method_callers = defaultdict(list)
    
    def __init__(self, method, callgraph, cfgs, graph_dir):
        self.method = method
        self.cfgs = cfgs
        self.method_callees = defaultdict(list)
        self.graph_dir = graph_dir
        self.callgraph = callgraph
        self.build_icfg()
    

    def build_icfg(self):
        self.add_copy_edge()
    
    def add_copy_edge(self):
        function_cfg = self.cfgs[self.method]
        
        #try:
        if self.callgraph.has_node(self.method):
            successors = self.callgraph.successors(self.method)

            for successor in successors:
                    block = self.callgraph[self.method][successor]['data']
                    basic_block_node = function_cfg.irblock_to_basicblock[block]
                    target_cfg = self.cfgs[successor]
                    pair = (function_cfg, basic_block_node)
                    ICFG.method_callers[successor].append(pair)
        '''
        except:
            print("here")
            IPython.embed()
        '''
            


