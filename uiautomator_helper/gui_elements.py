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

class GuiElements:
    def __init__(self, values):
        self.bounds = values[0]
        self.checkable = values[1]
        self.checked = values[2]
        self.class_name = values[3]
        self.clickable = values[4]
        self.content_desc = values[5]
        self.enabled = values[6]
        self.focusable = values[7]
        self.focused = values[8]
        self.index = values[9]
        self.long_clickable = values[10]
        self.package = values[11]
        self.password = values[12]
        self.resource_id = values[13]
        self.scrollable = values[14]
        self.selected = values[15]
        self.text = values[16]
        self.x = None
        self.y = None
        self.setup()

    def setup(self):
        left = self.bounds.split('][')[0]
        right = self.bounds.split('][')[1]
        first = left.split("[")[1].split(',')
        second = right.split(']')[0].split(',')
        self.x = int((int(first[0]) + int(second[0]))/2)
        self.y = int((int(first[1]) + int(second[1])) / 2)