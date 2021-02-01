'''
=======================
	Generic Imports
=======================
'''
import sys
sys.path.append("..")
import angr
import json
from pprint import pprint
from enum import Enum
from collections import defaultdict
from difflib import get_close_matches
import sys
import pickle
#import _pickle as pickle
import os, sys
import subprocess
from collections import defaultdict
from pyaxmlparser import APK
#import ipdb
import glob
#import IPython
import dill
from lib.helper import check_env_var
import re
import gc
import networkx as nx
import pydot
import pysoot

'''
=======================
	Global Variables
=======================
'''
PROJECT_ROOT = check_env_var('GOAL_EXPLORER') ## This should be the root directory of the project
SDK = check_env_var('SDK') ## Should be the android sdk root directory

'''
=======================
	Module Imports
=======================
'''
from hierarchy import *
from callgraph import *
from utils import *

'''
=======================
	Class Definitions
=======================
'''
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Define error codes
class Error(Enum):
    ENV_VAR_NOT_SET = 1
    FILE_NOT_FOUND = 2

class Apk:

	def __init__(self, apk_path, result_dir, log):
		self._all_cls = None
		self._hierarchy = None
		self._callgraph = None
		self._project_classes = {}
		self._methods = list()
		self._methods_key = {}
		self._blocks_to_methods = {}
		self._stmts_to_blocks = {}
		self._merged_callgraph = None
		self._stmts_to_classes = {}
		self.framework_callback_list = {}
		self.apk_potential_callbacks = defaultdict(list)
		self._apk_path = apk_path
		self.result_dir = result_dir
		self._apk = None
		self._apk_dep = None
		self._support_class_mapping = {}
		self.log = log
		self.setup()
	
	def setup(self):
		self._apk = APK(self._apk_path)
		package_name = self._apk.packagename
		sdk_path = os.path.join(SDK, "Sdk/platforms")

		angr_p = angr.Project(self._apk_path, main_opts={'android_sdk': sdk_path})
		all_cls = angr_p.loader.main_object.classes
		self._all_cls = all_cls

		
		for key, value in all_cls.items():
			if key.startswith(package_name):
				self._project_classes[key] = value

		for key, value in self._project_classes.items():
			for method in value.methods:
				self._methods.append(method)

		for cls_name, cls in self._project_classes.items():
			for method in cls.methods:
				method_key = get_method_key(method)
				self._methods_key[method_key] = method

				for block in method.blocks:
					self._blocks_to_methods[block] = method

					for stmt in block.statements:
						self._stmts_to_blocks[stmt] = block
						self._stmts_to_classes[stmt] = cls

		self._hierarchy = self.get_class_hierarchy()
		self._callgraph = self.get_callgraph()

	@property
	def project_classes(self):
		return self._project_classes

	# class hierarchy construction
	def get_class_hierarchy(self):
		if self._hierarchy is None:
			self._hierarchy = Hierarchy(self)
		return self._hierarchy


	def get_callgraph(self):
		if self._callgraph is None:
			self._callgraph = CallGraph(self, self.log)
		
		self._callgraph.log = None
		return self._callgraph

	@property
	def stmts_to_blocks(self):
		return self._stmts_to_blocks

	@property
	def stmts_to_classes(self):
		return self._stmts_to_classes
	
	@property
	def blocks_to_methods(self):
		return self._blocks_to_methods

	def methods(self):
		return self._methods_key

	def patch_constant_str_bool(self):
		# this patch update the str value of a bool constant in Slither IR
		# where originally it displays "True" but now "true" ("False" but now "false")
		# which corresponds with the Solidity language
		def new_str(self):
			method_name = self.class_name + "." + self.name + "()"
			return method_name
		pysoot.sootir.soot_method.SootMethod.__str__ = new_str


	def print_graph_dot(self, graph, graph_dir):
		content = ''

		self.patch_constant_str_bool()

		# if function.name == 'mul':
		# IPython.embed()
		# Ref: https://stackoverflow.com/questions/33722809/nx-write-dot-generates-redundant-nodes-when-input-nodes-have-a-colon
		dot_file_name = "callgraph" + ".dot"
		dot_file_path = os.path.join(graph_dir, dot_file_name)
		with open(dot_file_path, 'w', encoding='utf8') as fp:
			nx.drawing.nx_pydot.write_dot(graph, fp)

		(graph,) = pydot.graph_from_dot_file(dot_file_path)

		png_file_name = "callgraph" + ".png"
		png_file_path = os.path.join(graph_dir, png_file_name)
		graph.write_png(png_file_path)

