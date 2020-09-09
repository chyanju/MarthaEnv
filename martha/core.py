from typing import List, Any
import uiautomator
import sys
import traceback 

class MState():
	"""
	This stores states from both the static analyzer and andorid emulator.
	"""
	def __init__(self) -> None:
		pass

class MAction():
	"""
	This stores actions for both the static analyzer and android emulator.
	"""
	def __init__(self, subject: uiautomator.AutomatorDeviceObject, action) -> None:
		self._subject = subject
		self._action = action

class MAnalyzer():
	"""
	This is a wrapper for external static analyzer. 
	"""
	def __init__(self) -> None:
		pass

	def analyze(self) -> bool:
		"""
		This invokes the external analyzer to perform static analysis.
		Returns (bool): whether the operation is successful or not.
		"""
		pass

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
	def __init__(self, device: Any, analyzer: MAnalyzer) -> None:
		"""
		Arguments:
			device (Any): (FIXME) type should be Device, the device object provided by uiautomator
			analyzer (MAnalyzer): the analyzer
		"""
		self._device = device
		self._analyzer = analyzer
	
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


