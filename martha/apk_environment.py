import re
import json
import pickle
import gym
import igraph

from typing import List, Tuple, Any, Union, Dict
from gym.utils import seeding

from .gui_element import GuiElement
from .apk import Apk

class ApkEnvironment(gym.Env):

    def __init__(self, apk: Apk):
        self.apk = apk

        # inherited variables
        self.action_space = None
        self.observation_space = None

    def get_curr_state(self):
        pass
    
    def reset(self):
        pass

    def step(self, arg_action_id: int):
        pass

    def seed(self, arg_seed: int=None):
        pass

    def render(self, mode: str="human"):
        pass

    def close(self):
        pass

    # todo: Daniel
    def get_apk_call_graph(self, arg_apk: Apk) -> igraph.Graph:
        pass

    # todo: Daniel
    # this returns the corresponding vertex (node) from the call graph given an action
    def get_node_for_action(self, arg_call_graph: igraph.Graph, arg_action: GuiElement) -> igraph.Vertex:
        pass

    # todo: Li-el
    def get_abstract_whxml(self, arg_whxml: str, arg_nrow: int, arg_ncol: int, arg_nchannel: int) -> Any:
        pass