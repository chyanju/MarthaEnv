import subprocess
from threading import Thread
from queue import Queue, Empty
import re
import pickle
import sys

def enqueue_listeners(watcher):
    # fixme: maybe you should clear logcat
    # p = subprocess.Popen(["adb","logcat","-e","Martha"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = subprocess.Popen(["adb","logcat"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    while True:
        # sys.stdout.flush()
        # sys.stderr.flush()
        line = p.stdout.readline()
        line = line.decode("utf-8").strip()
        if line == '':
            continue
        watcher.raw_list.append(line)
        m = re.search(r"Martha.*?Reward=(.*)", line)
        if m:
            watcher.reward_list.append(float(m.group(1)))
            continue
        else:
            pass

class LogcatWatcher:
    def __init__(self):
        self.raw_list = []
        self.reward_list = []
        self.thread = Thread(target=enqueue_listeners, args=(self,)).start()

    def get_last_reward(self, clear=True):
        if len(self.reward_list)>0:
            ret = self.reward_list[-1]
            self.reward_list = []
            self.raw_list = []
            return ret
        else:
            self.reward_list = []
            self.raw_list = []
            return None
