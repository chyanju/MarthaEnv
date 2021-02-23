import subprocess
import sys
sys.path.append("../..")
import angr
from enum import Enum
import datetime
import argparse
import json
from pprint import pprint
from collections import defaultdict
from difflib import get_close_matches
import sys
import _pickle as pickle
import os
import subprocess
import logging
import frida
import time
import signal
import types
import time
import glob
import threading
from pyaxmlparser import APK
from lib.helper import *
from utils import *
import IPython
import networkx as nx
from wtg_node import *
from wtg_edge import *

class WTG:

    def __init__(self, wtg_root, log):
        self.wtg_root_dir = wtg_root
        self.launch_node = None
        self.wtg_graph = nx.MultiDiGraph()
        self.wtg = None
        self.nodes = {}
        self.edges = dict()
        self.log = log
        self.setup()

    def setup(self):
        wtg_dot_path = os.path.join(self.wtg_root_dir, 'wtg.dot')
        self.wtg = nx.drawing.nx_pydot.read_dot(wtg_dot_path)
        self.process_nodes(self.wtg.nodes._nodes)
        self.process_edges(self.wtg.edges._adjdict)
        self.map_actions_to_node()


    def process_nodes(self, wtg_nodes_dict):
        for node_key, node_value in wtg_nodes_dict.items():
            node = WTGNode(node_key, node_value['label'][1:-1])
            self.nodes[node_key] = node
            self.wtg_graph.add_node(node)

            if node.node_type == 'LAUNCHER_NODE':
                self.launch_node = node

    def map_actions_to_node(self):
        for node in self.wtg_graph.nodes:
            edges = list(set(list(self.wtg_graph.out_edges(node))))

            for edge in edges:
                for key in self.edges[edge[0]][edge[1]].keys():
                    wtg_edge_obj = self.edges[edge[0]][edge[1]][key]
                    node.available_actions[wtg_edge_obj] = wtg_edge_obj.get_actionable_resource()
        print("")

    def process_edges(self, wtg_adjdict):
        for src_node_key in wtg_adjdict.keys():
            for dest_node_key in wtg_adjdict[src_node_key].keys():
                for edge_id in wtg_adjdict[src_node_key][dest_node_key].keys():
                    edge_value = wtg_adjdict[src_node_key][dest_node_key][edge_id]
                    edge = WTGEdge(src_node_key, dest_node_key, edge_id, edge_value['label'][1:-1])

                    if self.edges.get(self.nodes[src_node_key]) is None:
                        self.edges[self.nodes[src_node_key]] = {}
                    if self.edges[self.nodes[src_node_key]].get(self.nodes[dest_node_key]) is None:
                        self.edges[self.nodes[src_node_key]][self.nodes[dest_node_key]] = {}

                    self.edges[self.nodes[src_node_key]][self.nodes[dest_node_key]][edge_id] = edge
                    self.wtg_graph.add_edge(self.nodes[src_node_key], self.nodes[dest_node_key], edge_id)
