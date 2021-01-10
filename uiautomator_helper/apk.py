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
from async_reader import *
from xml.etree import cElementTree as ElementTree
import xml.etree.ElementTree as ET
import IPython


class Apk:

    def __init__(self, apk_path, uiautomator_device, log):
        self.apk_path = apk_path
        self.uiautomator_device = uiautomator_device
        self.apk = None
        self.log = log
        self.logging = True
        self.debug = []
        self.goal_states = []
        self.setup()

    def install_apk(self):
        if self.check_if_app_exists(self.apk.packagename) is False:
            proc = subprocess.Popen(["adb", "install", self.apk_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()
            apk_base_name = os.path.basename(self.apk_path)

            if len(error.decode()) == 0:
                self.log.info("APK installtion done for %s" % apk_base_name)

            else:
                self.log.warning("Installation errored out for %s" % apk_base_name)
        else:
            self.log.info('%s is already installed' % os.path.basename(self.apk_path))

    def check_if_app_exists(self, target_package):
        proc = subprocess.Popen(["adb", "shell", "pm", "list", "packages"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        installed_packages = output.decode().splitlines()

        if target_package in installed_packages:
            return True
        return False

    def setup(self):
        self.clean_logcat()
        self.apk = APK(self.apk_path)
        self.install_apk()
        th = threading.Thread(target=self.start_logging)
        th.start()

        #self.start_logging()


    def enable_logging(self):
        self.logging = True

    def disable_loggin(self):
        self.logging = False

    def start_logging(self):
        # You'll need to add any command line arguments here.
        process = subprocess.Popen(['adb', 'logcat'], stdout=subprocess.PIPE)

        # Launch the asynchronous readers of the process' stdout.
        stdout_queue = Queue.Queue()
        stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
        stdout_reader.start()

        # Check the queues if we received some output (until there is nothing more to get).
        try:
            while self.logging and not stdout_reader.eof():
                while not stdout_queue.empty():
                    line = stdout_queue.get()

                    if "TRAIN DATA".encode() in line or "TEST DATA".encode() in line:
                        #print("Hoorah, I found it! " + str(datetime.datetime.now()))
                        self.goal_states.append(line)
                        break
        finally:
            process.kill()

    def clear_user_data(self):
        try:
            clear_command = "adb shell pm clear " + self.apk.packagename
            output = subprocess.check_output(clear_command, shell=True)
            PID = output.decode().strip()

            if PID != 'Success':
                self.log.info("User data can not be cleared, exiting")
                sys.exit(1)

            else:
                self.log.info("User data is already cleared.")

        except:
            pass

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
            main_activity = list(self.apk.get_main_activities())[0]
            if self.apk.packagename not in main_activity:
                main_activity = self.apk.packagename + "." + main_activity

            main_activity_path = self.apk.packagename + "/" + main_activity
            proc = subprocess.Popen(["adb", 'shell', 'am', 'start', '-n', main_activity_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()

            if len(error.decode()) == 0:
                self.log.info('Apk spawned successfully!')

            else:
                self.log.error('Issue with apk spawning, debug!')
                sys.exit(1)

        except Exception as e:
            raise e

    def launch_app(self):
        self.log.info("Kill the current app if already spawned!")
        self.clean_state()
        #time.sleep(1)

        self.log.info("Spawning the current app")
        self.spawn_apk()
        time.sleep(2)

    # Get the current device state in xml string
    # Right now this simply returns the xml window hierarchy
    def get_current_state(self):
        window_hierarchy = self.uiautomator_device.dump_hierarchy()
        return window_hierarchy


    def create_gui_element_object(self, xml_node):
        gui_obj = GuiElements(xml_node)
        return gui_obj

    # This function expects the current device state as an argument
    # and returns an array of actionable elements
    def get_available_actionable_elements(self, window_hierarchy):
        window_root = ET.XML(window_hierarchy)
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


    def get_reached_goal_states(self, goal_type):
        current_goal_states = []
        time.sleep(1)
        if goal_type == 'train':
            for state in self.goal_states:
                if "TRAIN DATA".encode() in state:
                    goal_state = state.decode().split("Goal instruction in ")[1].rsplit(" reached")[0]
                    current_goal_states.append(goal_state)

        else:
            for state in self.goal_states:
                if "TEST DATA".encode() in state:
                    goal_state = state.decode().split("Goal instruction in ")[1].rsplit(" reached")[0]
                    current_goal_states.append(goal_state)

        self.goal_states = []
        #self.clean_logcat()
        return current_goal_states

    def clean_logcat(self):
        proc = subprocess.Popen(["adb", "logcat", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        output = output.decode().strip()
        error = error.decode().strip()

        if len(error) == 0:
            self.log.info("Old logcat messages cleared!")
        else:
            self.log.warning("Error in logcat cleaning")

    def explore(self, uiautomator_device):
        window_hierarchy = self.get_current_state()
        available_actions = self.get_available_actionable_elements(window_hierarchy)
        self.perform_actions(uiautomator_device, available_actions)

    # This method is for performing a single action
    def perform_action(self, action):
        self.uiautomator_device.click(action.x, action.y)

    def perform_actions(self, uiautomator_device, available_actions):
        for action in available_actions:
            #if action.class_name == 'android.widget.LinearLayout' and action.index == '0':
            uiautomator_device.click(action.x, action.y)
            time.sleep(1)
            uiautomator_device.press('back')
            time.sleep(1)
