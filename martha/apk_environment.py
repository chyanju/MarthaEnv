import re
import json
import pickle
import gym
import igraph
import os
import time

import numpy as np

from typing import List, Tuple, Any, Union, Dict
from gym.utils import seeding

from .gui_element import GuiElement
from .apk import Apk
from .logcat_watcher import LogcatWatcher

# from screen import ScreenObject
# from saveScreen import ScreenData

class ApkEnvironment(gym.Env):
    SCREEN_MAX_ACTIONS = 100
    SCREEN_WIDTH = 600 # x, px
    SCREEN_HEIGHT = 1024 # y, px
    GRID_WIDTH = 30 # x
    GRID_HEIGHT = 32 # y
    RWIDTH = 20 # 600/30=20, x
    RHEIGHT = 32 # 1024/32=32, y
    # default screen resolution is: 600px * 1024px (x, y)
    # resterization grid is: 30px * 32px (x, y)
    # so number of grids is: 20 * 32 (x, y)
    # x: [0, 19], y: [0, 31], -1 is for nothing

    def __init__(self, config):
        self.config = config
        self.max_step = config["max_step"]

        # =========== #
        # apk related #
        # =========== #

        self.apk_path = "{}/{}".format(config["apk_folder"], config["apk_name"])
        self.apk = None
        self.apk_call_graph = None
        self.logcat_watcher = config["logcat_watcher"]

        self.curr_action_seq = None
        self.reset()

        # inherited variables
        self.action_space = gym.spaces.Discrete(ApkEnvironment.SCREEN_MAX_ACTIONS)
        self.observation_space = gym.spaces.Dict({
            # note: range of Box is inclusive
            "n_actions": gym.spaces.Box(0, ApkEnvironment.SCREEN_MAX_ACTIONS, shape=(1,), dtype=np.int32),
            "action_mask": gym.spaces.Box(0, 1, shape=(ApkEnvironment.SCREEN_MAX_ACTIONS,), dtype=np.int32),
            "action_x": gym.spaces.Box(-1, ApkEnvironment.RWIDTH-1, shape=(ApkEnvironment.SCREEN_MAX_ACTIONS,), dtype=np.int32),
            "action_y": gym.spaces.Box(-1, ApkEnvironment.RHEIGHT-1, shape=(ApkEnvironment.SCREEN_MAX_ACTIONS,), dtype=np.int32),
            "state": gym.spaces.Box(0, 1, shape=(ApkEnvironment.RHEIGHT, ApkEnvironment.RWIDTH), dtype=np.int32), # here we use the observed shape (y, x)
        })

    def get_curr_state(self):
        tmp_action_list = self.get_curr_actions()
        tmp_map = np.zeros((ApkEnvironment.RHEIGHT, ApkEnvironment.RWIDTH), dtype=np.int32)
        for p in tmp_action_list:
            tmp_pts = p.attributes["parsed_bounds"]
            # light up the rectangle zone in the map
            # note: use min to prevent overflow corner case, e.g., 600//30=20, which exceeds the upper bound
            tmp_rx0 = min( ApkEnvironment.RWIDTH-1, tmp_pts[0]//ApkEnvironment.GRID_WIDTH )
            tmp_rx1 = min( ApkEnvironment.RWIDTH-1, tmp_pts[2]//ApkEnvironment.GRID_WIDTH )
            tmp_ry0 = min( ApkEnvironment.RHEIGHT-1, tmp_pts[1]//ApkEnvironment.GRID_HEIGHT )
            tmp_ry1 = min( ApkEnvironment.RHEIGHT-1, tmp_pts[3]//ApkEnvironment.GRID_HEIGHT )
            for i in range(tmp_ry0, tmp_ry1+1):
                for j in range(tmp_rx0, tmp_rx1+1):
                    tmp_map[i,j] = 1

        return tmp_map

    def get_curr_actions(self):
        # forward to apk
        return self.apk.get_curr_actions()

    def get_action_repr(self, arg_action):
        # tmp_pts is the parsed bounds list: [x0,y0,x1,y1]
        # returns (rx,ry) of central point
        # note: use min to prevent overflow corner case, e.g., 600//30=20, which exceeds the upper bound
        tmp_pts = arg_action.attributes["parsed_bounds"]
        return (
            min( ApkEnvironment.RWIDTH-1, ((tmp_pts[0]+tmp_pts[2])//2)//ApkEnvironment.GRID_WIDTH ),
            min( ApkEnvironment.RHEIGHT-1, ((tmp_pts[1]+tmp_pts[3])//2)//ApkEnvironment.GRID_HEIGHT ),
        )

    def setup(self):
        self.apk = Apk(apk_path=self.apk_path)
        self.apk_call_graph = None

    def reset(self):
        print("# [debug] reset")
        self.setup()
        self.apk.clear_logcat()
        self.apk.launch_app()
        time.sleep(2)
        self.curr_action_seq = []

        tmp_action_list = self.get_curr_actions()
        # load the actions
        tmp_action_x = np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32)
        tmp_action_y = np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32)
        for i in range(len(tmp_action_list)):
            p = self.get_action_repr(tmp_action_list[i])
            tmp_action_x[i] = p[0]
            tmp_action_y[i] = p[1]

        # fixme
        return {
            "n_actions": [len(tmp_action_list)],
            "action_mask": [1 for _ in range(len(tmp_action_list))] + [0 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS-len(tmp_action_list))],
            "action_x": tmp_action_x,
            "action_y": tmp_action_y,
            "state": self.get_curr_state(),
        }

    def step(self, arg_action_id: int):
        tmp_action_list = self.get_curr_actions()

        if len(tmp_action_list)<=0:
            raise EnvironmentError("There is available action; the environment status is done.")

        # note: if this happens, directly return bad rewards
        #       because in exploration stage, the agent may sample non-existing id
        if arg_action_id >= len(tmp_action_list):
            # clear watcher
            _ = self.logcat_watcher.get_last_reward()
            # raise EnvironmentError("Action id is not in range, required: [0, {}), got: {}".format(len(tmp_action_list), arg_action_id))
            print("# [debug][terminate] action: {}".format(arg_action_id))
            return [
                {
                    "n_actions": [0],
                    "action_mask": [0 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)],
                    "action_x": np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32),
                    "action_y": np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32),
                    "state": self.get_curr_state(),
                },
                0.0, # 0 reward immediately since this is not allowed, and terminate
                True, # terminate!
                {}, # info
            ]

        self.apk.perform_action(tmp_action_list[arg_action_id])
        self.curr_action_seq = self.curr_action_seq + [arg_action_id]

        tmp_reward = self.logcat_watcher.get_last_reward()
        if tmp_reward is None:
            tmp_reward = 0.01

        tmp_terminate = None
        if len(self.curr_action_seq)>=self.max_step:
            tmp_terminate = True
        else:
            tmp_terminate = False

        # load the actions
        tmp_action_x = np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32)
        tmp_action_y = np.asarray([-1 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS)], dtype=np.int32)
        for i in range(len(tmp_action_list)):
            p = self.get_action_repr(tmp_action_list[i])
            tmp_action_x[i] = p[0]
            tmp_action_y[i] = p[1]

        print("# [debug] action: {}, seq: {}, reward: {}, terminate: {}".format(
            arg_action_id, self.curr_action_seq, tmp_reward, tmp_terminate
        ))
        return [
            {
                "n_actions": [len(tmp_action_list)],
                "action_mask": [1 for _ in range(len(tmp_action_list))] + [0 for _ in range(ApkEnvironment.SCREEN_MAX_ACTIONS-len(tmp_action_list))],
                "action_x": tmp_action_x,
                "action_y": tmp_action_y,
                "state": self.get_curr_state(),
            },
            tmp_reward, # reward is 0.01 since it after all succeeded
            tmp_terminate,
            {}, # info
        ]

    def seed(self, arg_seed: int=None):
        self.np_random, seed = seeding.np_random(seed)
        return [seed]

    def render(self, mode: str="human"):
        pass

    def close(self):
        pass
       

