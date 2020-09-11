from typing import List, Any
import uiautomator
import sys
import traceback 
import subprocess
import re

class MState():
	"""
	This stores states from both the static analyzer and andorid emulator.
	"""
	def __init__(self, name : str, label : str) -> None:
		self._name = name
		self._label = label
		print("In STATE ctor, vals: ", self._name, self._label)

	def to_string(self):
		return "Name: "+self._name+" Label: "+self._label
	'''
	for now, just node name and label (might not be necessary but keep just in case)
	'''

class MEdge():
	'''
	A edge between 2 MStates- holds 2 states and the event that triggers the transition
	'''
	def __init__(self, source:MState, dest:MState, event:str, widget:str) -> None:
		'''
		2 node objects - in and out
		widget and event (can be compared to an MAction obj- need to figure out how to compare widget info to UIObj)
		'''
		self._source = source
		self._dest = dest
		self._event = event
		self._widget = widget
	
	def to_string(self):
		return "Source: "+self._source._name+" Dest: "+self._dest._name+" Evt: "+self._event+" Widget: "+self._widget

class MGraph():
	'''
	Represents the global window transition graph of the app
	Basically a python wrapper of the WTG object generated by GATOR
	'''
	'''
		list (dictionary?) of nodes
		list of edges
	'''
	def __init__(self, node_dict, edge_list)->None:
		self._node_dict = node_dict
		self._edge_list = edge_list
		self._init_node = node_dict['n1']	#TODO- make sure that this is assigned to the actual init node, not just the launcher
		# --> find the LAUNCHER NODE and the corresponding implicit_launch_event transition- the destination of that edge is the starting node
		self._current_node = 0	#to track current location in graph as actions are taken to traverse it

class MAction():
	"""
	This stores actions for both the static analyzer and android emulator.
	"""
	def __init__(self, subject: uiautomator.AutomatorDeviceObject, action) -> None:
		'''
			subject: the object found by uiautomator that the action will be called from
			action: a lambda function that calls a specific action from the provided uiobject
		'''
		self._subject = subject
		self._action = action

class MAnalyzer():
	"""
	This is a wrapper for external static analyzer. 
	"""
	def __init__(self, binary_path, target_apk) -> None:
		self._binary_path = binary_path
		self._target_apk = target_apk

	def analyze(self) -> MGraph:
		"""
		This invokes the external analyzer to perform static analysis.
		Returns (bool): whether the operation is successful or not.
		"""
		# call the GATOR executable and dump the WTG of the provided APK to the file 'wtg.dot'
		# then deconstruct the WTG in that file to construct the global graph of the app as an MGraph object
		# for now, just parsing names and labels, not using stack info in wtg
		analyze_command = './'+self._binary_path+' a -p '+self._target_apk+ ' -client WTGDumpClient'
		
		try:
			call_result = subprocess.check_output(analyze_command, shell=True)
			print("Analysis successfully completed!")
		except subprocess.CalledProcessError as exec_err:
			print("Analyzer failed with the following err code: ", exec_err.returncode, exec_err.output)
			return None

		#open graph.txt to parse into MGraph
		graph_name = 'wtg.dot'
		constructed_graph : MGraph = None
		node_dict = {}
		edge_list = []

		with open(graph_name, 'r') as graph_file:
			for line in graph_file:
				print(line)
				# node_re = re.compile('?P<node_name> [label="?P<node_label>"];')
				print("HERE")
				# m = re.match(node_re,line)
				# m = re.split('(.*) (\[label=".*"\];)', line)
				if "label" in line:
					if "->" in line:
					
						print("Trying to match on EDGE pattern")
						edge_re = '(.+?)->+(.+?) \[label=".*evt: (.*?)\\\\nwidget: (.*?)\\\\nhandler.*"\];'
						edge_params = re.split(edge_re, line)
						print("Post EDGE match, gonna try to get split vals")
						edge_params = [x for x in edge_params if (x and not x.isspace())]
						if edge_params:
							print("matched")
							for x in edge_params:
								print("SEC LOOP: ", x)
							source_node = edge_params[0].strip()
							dest_node = edge_params[1].strip()
							edge_event = edge_params[2].strip()
							edge_widget = edge_params[3].strip()
							edge_list.append(MEdge(node_dict[source_node], node_dict[dest_node], edge_event, edge_widget))
						else:
							print("not a match")

					else:
						print("Trying to match on NODE pattern")
						node_re = '(.*) \[label="(.*)"\];'
						node_params = re.split(node_re, line)
						print("Post NODE match, gonna try to get split vals")
						node_params = [x for x in node_params if (x and not x.isspace())]
						if node_params:
							print("matched")
							for x in node_params:
								print("SEC LOOP: ", x)
							curr_node = MState(node_params[0].strip(), node_params[1].strip())
							node_dict[node_params[0].strip()] = curr_node
							print("AFTER ADDING NODE TO DICT")
						else:
							print("not a match")

		print("\nAfter matching stuff, here are those lists yeee\n")
		print("NODES")
		for x in node_dict.keys():
			print(x," : ", node_dict[x].to_string())

		print("EDGES")
		for x in edge_list:
			print(x.to_string())

		if node_dict and edge_list:
			constructed_graph = MGraph(node_dict, edge_list)

		print("end, about to return true")
		return constructed_graph


	def state_shortest_distance(self, s0: MState, s1: MState) -> float:
		"""
		This computes the shortest distance between two states.
		Returns (float): the distance.
		"""
		pass

class MEnvironment():
	"""
	Main interactive environment class; the environment is stateful.
	"""
	# def __init__(self, device: Any, analyzer: MAnalyzer) -> None:
	def __init__(self, device: Any, global_graph: MGraph) -> None:
		"""
		Arguments:
			device (Any): (FIXME) type should be Device, the device object provided by uiautomator
			analyzer (MAnalyzer): the analyzer
		"""
		self._device = device
		# self._analyzer = analyzer
		self._global_graph = global_graph

		#TODO- seems like the env should have a GRAPH member var, passed in after being generated by the analyzer, not an analyzer mem var
	
	def reset(self) -> bool:
		"""
		Reset the status of the current device/emulator;
		will also reset the alignment between analyzer and device/emulator
		Returns (bool): whether the operation is successful or not.
		"""
		pass

	def get_current_device_state(self) -> MState:
		"""
		Access the current state.
		Returns (MState): the current states of the device/emulator you are in.
		"""
		pass

	def get_current_analyzer_state(self) -> MState:
		"""
		Access the current state.
		Returns (MState): the current states of the analyzer you are in.
		"""
		pass

# TODO: right now, just returns list of 'click' actions with subjects- generalize to all possible actions on all active objects later!
	def get_available_actions(self) :#-> List[MAction]:
		"""
		Given the current internal status, return the user a list of available actions.
		Returns (List[MAction]): a list of available actions for the current state of emulator.
		"""
		first_try = self._device(classNameMatches="android.widget.*")

		action_list = []

		for i in first_try:
			if i.info['clickable']:
				action_list.append( MAction(i, lambda x : x.click()))
		return action_list

	def take_action(self, action: MAction) -> bool:
		"""
		Execute the provided action on both the device/emulator and analyzer.
		Returns (bool): whether the action is executed successfully.
		"""
		try:
			action._action(action._subject)
			print("Action successful! :)")
			return True
		except:
			print ("The action could not be executed :(")
			# print("STACK TRACE: ")
			# traceback.print_exc()
		return False

	def align(self) -> bool:
		"""
		Align the analyzer state to the current state of the device/emulator.
		Returns (bool): whether the operation is successful or not.
		"""
		pass


