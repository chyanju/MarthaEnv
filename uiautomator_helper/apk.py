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

SYSTEM_EVENTS = ['home', 'rotate', 'back', 'power','launch']
class Apk:

    def __init__(self, apk_path, uiautomator_device, output_dir, log):
        self.apk_path = apk_path
        self.uiautomator_device = uiautomator_device
        self.apk = None
        self.current_state = None
        self.current_available_actions = []
        self.log = log
        self.logging = True
        self.debug = []
        self.output_dir = output_dir
        self.goal_states = []
        self.resource_id_to_name = {}
        self.resource_name_to_content = {}
        self.static_to_dynamic_matching = defaultdict(list)
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
        self.apk.get_android_resources()._analyse()
        self.populate_resource_ids()
        self.install_apk()
        th = threading.Thread(target=self.start_logging)
        th.start()

        #self.start_logging()
    def populate_resource_ids(self):
        arsc_parser = self.apk.arsc['resources.arsc']
        for res_type in self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename].keys():
            for res_name in self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename][res_type].keys():
                res_id = self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename][res_type][res_name]
                self.resource_id_to_name[str(res_id)] = res_name

        locale = '\x00\x00'
        for value_pair in arsc_parser.values[self.apk.packagename][locale]['string']:
            self.resource_name_to_content[value_pair[0]] = value_pair[1]

    def enable_logging(self):
        self.logging = True

    def disable_loggin(self):
        self.logging = False

    def start_logging(self):
        # You'll need to add any command line arguments here.
        process = subprocess.Popen(['adb', 'logcat'], stdout=subprocess.PIPE)
        start_time = time.time()
        # Launch the asynchronous readers of the process' stdout.
        stdout_queue = Queue.Queue()
        stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
        stdout_reader.start()

        # Check the queues if we received some output (until there is nothing more to get).
        try:
            while not stdout_reader.eof():
                while not stdout_queue.empty():
                    if not self.logging:
                        process.kill()
                        return

                    line = stdout_queue.get()

                    if "TRAIN DATA".encode() in line or "TEST DATA".encode() in line:
                        #print("Hoorah, I found it! " + str(datetime.datetime.now()))
                        hit_time = time.time()
                        self.goal_states.append(line)
                        strline = "Goal state %s has been found after %f seconds" % (line, hit_time - start_time)

                        ## write goal states to a file
                        file_path = os.path.join(self.output_dir, "logcat.txt")
                        with open(file_path, 'a+') as f:
                            f.write("%s\n" % strline)
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
                if main_activity.startswith("."):
                    main_activity = self.apk.packagename + main_activity

                else:
                    main_activity = self.apk.packagename + "." + main_activity

            main_activity_path = self.apk.packagename + "/" + main_activity
            proc = subprocess.Popen(["adb", 'shell', 'am', 'start', '-S', '-n', main_activity_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        self.current_state = window_hierarchy
        return self.current_state

    def get_match_score(self, s_sctions, d_actions):
        match_score = 0
        explit_actions = 0
        for s_action in s_sctions:
            if s_action['name'] in SYSTEM_EVENTS:
                continue
            explit_actions += 1
            for d_action in d_actions:
                s_res_id = s_action['id']
                s_res_name = 'NaN'
                s_res_content = 'NaN'
                if self.resource_id_to_name.get(s_res_id) is not None:
                    s_res_name = self.resource_id_to_name[s_res_id]
                    if self.resource_name_to_content.get(s_res_name) is not None:
                        s_res_content = self.resource_name_to_content[s_res_name]

                d_action_summary = d_action.element_summary
                if s_res_id in d_action_summary or s_res_name in d_action_summary or s_res_content in d_action_summary:
                    self.static_to_dynamic_matching[d_action].append(s_action)
                    match_score += 1
                    break

        return match_score, explit_actions

    def get_wtg_graph(self, wtg_obj):
        return wtg_obj.wtg_graph

    def get_current_activity(self):
        cmd = "adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'"
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode().strip().splitlines()
        current_activity = None

        if output!= '' and "/" in output[0]:
            current_activity = output[0].split("/")[1].split("}")[0]

        return current_activity

    def get_wtg_state(self, wtg_obj):
        max_match_score = 0
        potential_target_nodes = []
        current_activity_class_name = self.get_current_activity()
        wtg_graph = wtg_obj.wtg_graph
        dynamic_available_actions = self.current_available_actions

        for node in wtg_graph.nodes:
            if current_activity_class_name is not None and current_activity_class_name not in node.node_value:
                continue
            static_available_actions = list(node.available_actions.values())
            match_score, explicit_actions = self.get_match_score(static_available_actions, dynamic_available_actions)

            if explicit_actions != 0 and len(dynamic_available_actions) != 0:
                if match_score >= max_match_score:
                    max_match_score = match_score
                    potential_target_nodes = []
                    potential_target_nodes.append(node)

            if explicit_actions == 0 and len(dynamic_available_actions) == 0:
                if not node.node_value.startswith('LAUNCHER_NODE'):
                    potential_target_nodes.append(node)

        return potential_target_nodes

    def create_gui_element_object(self, xml_node):
        gui_obj = GuiElements(xml_node)
        return gui_obj


    def get_matching_dynamic_action_to_static_action(self, dynamic_action, wtg_obj):
        potential_target_nodes = self.get_wtg_state(wtg_obj)
        already_matched_static_actions = []
        potential_static_actions = []
        matched_edges = []

        for d_action in self.current_available_actions:
            if self.static_to_dynamic_matching.get(d_action) is not None:
                if dynamic_action == d_action:
                    potential_static_actions.extend(self.static_to_dynamic_matching[dynamic_action])
                else:
                    already_matched_static_actions.extend(self.static_to_dynamic_matching[d_action])


        for target_node in potential_target_nodes:
            for edge in target_node.available_actions.keys():
                static_action = target_node.available_actions[edge]

                if static_action['name'] in SYSTEM_EVENTS:
                    continue

                if static_action in potential_static_actions:
                    matched_edges.append(edge)
                    break

                else:
                    if static_action in already_matched_static_actions:
                        continue

                    else:
                        if edge not in matched_edges:
                            matched_edges.append(edge)

        wtg_edges = []
        for matched_edge in matched_edges:
            src_node = wtg_obj.nodes[matched_edge.src_node_key]
            dest_node = wtg_obj.nodes[matched_edge.dest_node_key]
            wtg_edges.append((src_node, dest_node, matched_edge.edge_id))

        return wtg_edges

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
                package_index = all_keys.index('package')
                all_items = top_element.items()

                if all_items[index][1] == 'true' and all_items[package_index][1] == self.apk.packagename:
                    gui_obj = self.create_gui_element_object(top_element)
                    clickable_gui_elements.append(gui_obj)

        self.current_available_actions = clickable_gui_elements
        return self.current_available_actions


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
