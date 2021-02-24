import subprocess
import sys
sys.path.append("..")
from enum import Enum
import datetime
import argparse
import networkx as nx
#from uiautomator import Device
import uiautomator2 as u2
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
from lib import *
from shutil import rmtree
from apk import *
from wtg import *

def get_device_serial(log):
    device_serial = None
    proc = subprocess.Popen(["adb", 'get-serialno'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()

    if len(error.decode()) == 0:
        all_serials = output.splitlines()

        if len(all_serials) > 1:
            log.warning("Multiple devices are connected to ADB!")

        # Always pick the 0th device serial
        device_serial = all_serials[0].decode().strip()

    return device_serial


def get_window_hierarchy(uiautomator_device):
    window_hierarchy = uiautomator_device.dump()
    return window_hierarchy

def run_adb_as_root(log):
    proc = subprocess.Popen(["adb", "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()
    output = output.decode().strip()
    error = error.decode().strip()

    if len(error) == 0:
        if output == 'adbd is already running as root' or output == 'restarting adbd as root':
            log.info("Adb is running with root priviledges now!")

        else:
            log.info("Some other error happened, debug!")
    else:
        log.warning("Error occured during adb command, debug!")


if __name__ == "__main__":
    MarthaEnv = os.path.dirname(os.getcwd())
    OUTPUT_DIR = os.path.join(MarthaEnv, "results")

    parser = argparse.ArgumentParser(description='Explore actions in the app using uiautomator')
    parser.add_argument('-p', '--path', help='provide full path of the apk')
    parser.add_argument('-w', '--wtginput', help='The path to WTG')
    parser.add_argument('-o', '--output', default=OUTPUT_DIR, help='path to the location where output will be stored')
    parser.add_argument('-gs', '--goalstates', help='path to the location where output will be stored')

    args = parser.parse_args()

    if args.path is not None:
        pyaxmlparser_apk = APK(args.path)
        apk_base_name = os.path.splitext(os.path.basename(args.path))[0]

    else:
        parser.print_usage()
        sys.exit(1)

    goal_states = {}
    if args.goalstates is not None:
        with open(args.goalstates, 'r') as fp:
            goal_states = json.load(fp)

    else:
        parser.print_usage()
        sys.exit(1)

    if args.output is not None:
        OUTPUT_DIR = args.output

    output_dir = os.path.join(OUTPUT_DIR, 'exploration_output', apk_base_name)

    wtg = None
    if args.wtginput:
        wtg = os.path.join(args.wtginput, apk_base_name)

    if os.path.exists(output_dir):
        rmtree(output_dir)

    os.makedirs(output_dir, exist_ok=True)

    # Setting the path for log file
    log_path = os.path.join(output_dir, 'analysis.log')
    log = init_logging('analyzer.%s' % apk_base_name, log_path, file_mode='w', console=True)

    # Record analysis start time
    now = datetime.datetime.now()
    analysis_start_time = now.strftime(DATE_FORMAT)
    info('Analysis started at: %s' % analysis_start_time)
    start_time = time.time()

    # Get the serial for the device attached to ADB
    device_serial = get_device_serial(log)

    if device_serial is None:
        log.warning("Device is not connected!")
        sys.exit(1)


    # Initialize the uiautomator device object using the device serial
    uiautomator_device = u2.connect(device_serial)
    run_adb_as_root(log)
    apk_obj = Apk(args.path, uiautomator_device, output_dir, log)
    wtg_obj = WTG(wtg, log)
    wtg_obj.set_goal_nodes(goal_states)

    apk_obj.launch_app()

    time.sleep(5)
    state = apk_obj.get_current_state()
    all_actions = apk_obj.get_available_actionable_elements(state)
    edges = apk_obj.get_matching_dynamic_action_to_static_action(all_actions[0], wtg_obj)

    #apk_obj.get_wtg_state(wtg_obj)
    input()
    #apk_obj.is_target_state()
    #print("")
    ## This is commented right now
    #apk_obj.explore(uiautomator_device)
