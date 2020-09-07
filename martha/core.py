from typing import List, Any

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
	def __init__(self) -> None:
		pass

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

	def get_available_actions(self) -> List[MAction]:
		"""
		Given the current internal status, return the user a list of available actions.
		Returns (List[MAction]): a list of available actions for the current state of emulator.
		"""
		pass

	def take_action(self, action: MAction) -> bool:
		"""
		Execute the provided action on both the device/emulator and analyzer.
		Returns (bool): whether the action is executed successfully.
		"""
		pass

	def align(self) -> bool:
		"""
		Align the analyzer state to the current state of the device/emulator.
		Returns (bool): whether the operation is successful or not.
		"""
		pass


