import sys
import os
import subprocess
import time
import threading
try:
  import Queue
except ImportError:
  import queue as Queue
import uiautomator2 as u2
import xml.etree.ElementTree as ET

from .gui_element import GuiElement
from .async_reader import AsynchronousFileReader
from .helper import init_logging
from pyaxmlparser import APK

SYSTEM_EVENTS = ['home', 'rotate', 'back', 'power','launch']
class Apk:

    def __init__(self, apk_path):
        self.device_serial = None
        self.uiautomator_device = None
        self.apk = None

        self.apk_path = apk_path
        self.apk_base_name = os.path.splitext(os.path.basename(apk_path))[0]
        self.logger = init_logging("analyzer.{}".format(self.apk_base_name), console=True)
        self.logging = True
        self.resource_id_to_name = {}
        self.resource_name_to_id = {}
        self.resource_name_to_content = {}
        self.setup()

    def setup(self):
        self.device_serial = self.get_device_serial()
        self.uiautomator_device = u2.connect(self.device_serial)
        self.clear_logcat()
        self.apk = APK(self.apk_path)
        self.apk.get_android_resources()._analyse()
        self.populate_resource_ids()
        self.install_apk()
        # th = threading.Thread(target=self.start_logging)
        # th.start()

    def get_device_serial(self):
        device_serial = None
        proc = subprocess.Popen(["adb", 'get-serialno'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        if len(error.decode()) == 0:
            all_serials = output.splitlines()
            if len(all_serials) > 1:
                self.logger.warning("Multiple devices are connected to ADB!")
            # Always pick the 0th device serial
            device_serial = all_serials[0].decode().strip()
        return device_serial

    def run_adb_as_root(self):
        proc = subprocess.Popen(["adb", "-s", self.device_serial, "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        output = output.decode().strip()
        error = error.decode().strip()
        if len(error) == 0:
            if output == 'adbd is already running as root' or output == 'restarting adbd as root':
                self.logger.info("Adb is running with root priviledges now!")
            else:
                self.logger.info("Some other error happened, debug!")
        else:
            self.logger.warning("Error occured during adb command, debug!")

    # fixme: need to perform clean installation every time no matter whether the app exists or not
    def install_apk(self):
        if self.check_if_app_exists(self.apk.packagename) is False:
            proc = subprocess.Popen(["adb", "-s", self.device_serial, "install", self.apk_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()
            apk_base_name = os.path.basename(self.apk_path)
            if len(error.decode()) == 0:
                self.logger.info("APK installtion done for %s" % apk_base_name)
            else:
                self.logger.warning("Installation errored out for %s" % apk_base_name)
        else:
            self.logger.info('%s is already installed' % os.path.basename(self.apk_path))

    def check_if_app_exists(self, target_package):
        proc = subprocess.Popen(["adb", "-s", self.device_serial, "shell", "pm", "list", "packages"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        installed_packages = output.decode().splitlines()
        if target_package in installed_packages:
            return True
        return False

    def populate_resource_ids(self):
        arsc_parser = self.apk.arsc['resources.arsc']
        for res_type in self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename].keys():
            for res_name in self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename][res_type].keys():
                res_id = self.apk.arsc['resources.arsc'].resource_keys[self.apk.packagename][res_type][res_name]
                self.resource_id_to_name[str(res_id)] = res_name
                self.resource_name_to_id[res_name]=str(res_id)
        locale = '\x00\x00'
        for value_pair in arsc_parser.values[self.apk.packagename][locale]['string']:
            self.resource_name_to_content[value_pair[0]] = value_pair[1]

    # def start_logging(self):
    #     process = subprocess.Popen(['adb', '-s', self.device_serial, 'logcat'], stdout=subprocess.PIPE)
    #     start_time = time.time()
    #     # launch the asynchronous readers of the process' stdout
    #     stdout_queue = Queue.Queue()
    #     stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
    #     stdout_reader.start()
    #     # check the queues if we received some output (until there is nothing more to get)
    #     try:
    #         while not stdout_reader.eof():
    #             while not stdout_queue.empty():
    #                 if not self.logging:
    #                     process.kill()
    #                     return
    #                 line = stdout_queue.get()
    #                 # fixme: add goal state checking commands
    #                 if "TRAIN DATA".encode() in line or "TEST DATA".encode() in line:
    #                     pass
    #     finally:
    #         process.kill()

    def clear_user_data(self):
        try:
            clear_command = "adb -s %s shell pm clear %s" %(self.device_serial, self.apk.packagename)
            output = subprocess.check_output(clear_command, shell=True)
            PID = output.decode().strip()
            if PID != 'Success':
                self.logger.info("User data can not be cleared, exiting")
                sys.exit(1)
            else:
                self.logger.info("User data is already cleared.")
        except:
            pass

    def kill_app(self):
        try:
            kill_command = "adb" + " -s " + self.device_serial + " shell ps | grep " + self.apk.packagename + " | awk '{print $2}'"
            output = subprocess.check_output(kill_command, shell=True)
            PID = output.decode().strip()
            if PID != '':
                proc = subprocess.Popen(["adb", '-s', self.device_serial, 'shell', 'kill', PID], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = proc.communicate()
                if len(error.decode()) == 0:
                    self.logger.info("APK killed")
                else:
                    self.logger.info("APK can not be killed, exiting")
                    sys.exit(1)
            else:
                self.logger.info("APK is already killed")
        except:
            pass

    def clean_state(self):
        try:
            self.kill_app()
        except ApkKilled as ak:
            pass

    def spawn_apk(self):
        try:
            main_activity = list(self.apk.get_main_activities())[0]
            if self.apk.packagename not in main_activity:
                if main_activity.startswith("."):
                    main_activity = self.apk.packagename + main_activity
                elif main_activity.startswith('com'):
                    pass
                else:
                    main_activity = self.apk.packagename + "." + main_activity
            main_activity_path = self.apk.packagename + "/" + main_activity
            proc = subprocess.Popen(["adb", '-s', self.device_serial, 'shell', 'am', 'start', '-S', '-n', main_activity_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()
            if len(error.decode()) == 0:
                self.logger.info('Apk spawned successfully!')
            else:
                self.logger.error('Issue with apk spawning, debug!')
                sys.exit(1)
        except Exception as e:
            raise e

    def launch_app(self):
        self.logger.info("Kill the current app if already spawned!")
        self.clean_state()
        self.logger.info("Spawning the current app")
        self.spawn_apk()
        # fixme: there's a 2s time interval
        time.sleep(2)

    def get_curr_whxml(self):
        return self.uiautomator_device.dump_hierarchy()

    # def get_current_activity(self):
    #     cmd = "adb" + " -s " + self.device_serial + " shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'"
    #     output = subprocess.check_output(cmd, shell=True)
    #     output = output.decode().strip().splitlines()
    #     current_activity = None
    #     if output!= '' and "/" in output[0]:
    #         current_activity = output[0].split("/")[1].split("}")[0]
    #     return current_activity

    # This function expects the current device state as an argument
    # and returns an array of actionable elements
    def get_curr_actions(self):
        window_hierarchy = self.get_curr_whxml()
        window_root = ET.XML(window_hierarchy)
        bfs_queue = []
        bfs_queue.append(window_root)
        clickable_gui_elements = []
        while len(bfs_queue) != 0:
            top_element = bfs_queue.pop()
            # children = top_element.getchildren()
            children = list(top_element)
            bfs_queue.extend(children)
            if 'clickable' in top_element.keys():
                all_keys = top_element.keys()
                index = all_keys.index('clickable')
                package_index = all_keys.index('package')
                all_items = top_element.items()
                if all_items[index][1] == 'true' and all_items[package_index][1] == self.apk.packagename:
                    gui_obj = GuiElement(top_element)
                    clickable_gui_elements.append(gui_obj)
        return clickable_gui_elements

    def clear_logcat(self):
        # proc = subprocess.Popen(["adb", "-s", self.device_serial, "logcat", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc = subprocess.Popen(["adb", "logcat", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        output = output.decode().strip()
        error = error.decode().strip()
        if len(error) == 0:
            self.logger.info("Old logcat messages cleared!")
        else:
            self.logger.warning("Error in logcat cleaning")

    # This method is for performing a single action
    def perform_action(self, action):
        self.uiautomator_device.click(action.x, action.y)
