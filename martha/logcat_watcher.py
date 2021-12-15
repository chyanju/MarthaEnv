import subprocess
from threading import Thread
import re
import pickle
import sys

class LogcatWatcher:
    def __init__(self):
        self.last_lines = []
        self.last_rewards = []

    def clear_logcat(self, force=False):
        while True:
            proc = subprocess.Popen(["adb", "logcat", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()
            output = output.decode().strip()
            error = error.decode().strip()
            if len(error) == 0:
                # good
                break
            else:
                if force:
                    # need to make sure it's cleared, enter while again
                    continue
                else:
                    # no need 
                    break

    def get_logcat_lines(self, kw="Martha"):
        # use -d to dump the content and exit while not jamming the process
        p = subprocess.Popen(["adb","logcat","-e",kw,"-d"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        lines = p.stdout.readlines()
        return [line.decode('utf-8') for line in lines]

    def get_last_reward(self, clear=True):
        self.last_lines = self.get_logcat_lines()
        self.last_rewards = [] # don't forget to clear

        for line in self.last_lines:
            dline = line.strip()
            if dline == '':
                continue
            m = re.search(r"Martha.*?Reward=(.*)", dline)
            if m:
                self.last_rewards.append(float(m.group(1)))
                continue
            # else: do nothing

        if clear:
            # no need to clear for getting reward
            self.clear_logcat()

        if len(self.last_rewards)>0:
            return self.last_rewards[-1]
        else:
            return None
