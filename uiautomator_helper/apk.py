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
from gui_elements import *
from xml.etree import cElementTree as ElementTree
import xml.etree.ElementTree as ET
import IPython

class Apk:

    def __init__(self, apk_path, log):
        self.apk_path = apk_path
        self.apk = None
        self.log = log
        self.setup()

    def setup(self):
        self.apk = APK(self.apk_path)

    def kill_app(self):
        try:
            kill_command = "adb shell ps | grep " + self.apk.packagename + " | awk '{print $2}'"
            output = subprocess.check_output(kill_command, shell=True)
            PID = output.decode().strip()

            if PID != '':
                proc = subprocess.Popen(["adb", 'shell', 'kill', PID], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = proc.communicate()

                if len(error.decode()) == 0:
                    self.log.info("APK killed")

                else:
                    self.log.info("APK can not be killed, exiting")
                    sys.exit(1)

            else:
                self.log.info("APK is already killed")

        except:
            pass

    def terminate(self):
        self.kill_app()

    def clean_state(self):
        try:
            self.terminate()
        except ApkKilled as ak:
            pass

    def spawn_apk(self):
        try:
            main_activity_path = self.apk.packagename + "/" + list(self.apk.get_main_activities())[0]
            proc = subprocess.Popen(["adb", 'shell', 'am', 'start', '-n', main_activity_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()

        except Exception as e:
            raise e

    def launch_app(self):
        self.log.info("Kill the current app if already spawned!")
        self.clean_state()
        #time.sleep(1)

        self.log.info("Spawning the current app")
        self.spawn_apk()
        time.sleep(2)

    def get_current_window_hierarchy(self, uiautomator_device):
        window_hierarchy = uiautomator_device.dump()
        window_root = ET.XML(window_hierarchy)
        return window_root


    def create_gui_element_object(self, xml_node):
        values = []
        for item in xml_node.items():
            values.append(item[1])

        gui_obj = GuiElements(values)

        return gui_obj

    def get_available_actionable_elements(self, window_root):
        bfs_queue = []
        bfs_queue.append(window_root)
        clickable_gui_elements = []

        while len(bfs_queue) != 0:
            top_element = bfs_queue.pop()
            children = top_element.getchildren()
            bfs_queue.extend(children)

            if 'clickable' in top_element.keys():
                all_keys = top_element.keys()
                index = all_keys.index('clickable')
                all_items = top_element.items()

                if all_items[index][1] == 'true':
                    gui_obj = self.create_gui_element_object(top_element)
                    clickable_gui_elements.append(gui_obj)

        return clickable_gui_elements

    def explore(self, uiautomator_device):
        window_root = self.get_current_window_hierarchy(uiautomator_device)

        # For now we just find gui elements which are clickable
        available_actions = self.get_available_actionable_elements(window_root)
        self.perform_actions(uiautomator_device, available_actions)

    def perform_actions(self, uiautomator_device, available_actions):
        for action in available_actions:
            #if action.class_name == 'android.widget.LinearLayout' and action.index == '0':
            uiautomator_device.click(action.x, action.y)
            time.sleep(1)
            uiautomator_device.press('back')
            time.sleep(1)