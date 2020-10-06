import subprocess
import sys
sys.path.append("..")
from enum import Enum
import datetime
import argparse
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

MarthaEnv = '/home/priyanka/research/projects/MarthaEnv'
OUTPUT_DIR = os.path.join(MarthaEnv, "results")

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Explore actions in the app using uiautomator')
    parser.add_argument('-p', '--path', help='provide full path of the apk')
    parser.add_argument('-o', '--output', default=OUTPUT_DIR, help='path to the location where output will be stored')

    args = parser.parse_args()

    if args.path is not None:
        pyaxmlparser_apk = APK(args.path)
        apk_base_name = os.path.splitext(os.path.basename(args.path))[0]

    else:
        parser.print_usage()

    if args.output is not None:
        OUTPUT_DIR = args.output

    output_dir = os.path.join(OUTPUT_DIR, apk_base_name)

    if os.path.exists(output_dir):
        rmtree(output_dir)

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

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
    apk_obj = Apk(args.path, log)
    apk_obj.launch_app()
    apk_obj.explore(uiautomator_device)
