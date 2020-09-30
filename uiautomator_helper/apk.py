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
        time.sleep(1)

        self.log.info("Spawning the current app")
        self.spawn_apk()

    def explore(self):
        pass