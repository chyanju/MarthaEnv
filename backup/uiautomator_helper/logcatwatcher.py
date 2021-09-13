import subprocess
from threading import Thread
from queue import Queue, Empty
import re

def enqueue_listeners(watcher):
    p = subprocess.Popen(["adb","logcat","-e","MARTHA"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    for line in p.stdout:
        m = re.match('.*MARTHA: setOnClickListener (\d+) to (.*)\n',line.decode("utf-8"))
        if m:
            watcher.click_queue.put((int(m.group(1)),m.group(2)))

class LogcatWatcher:
    def __init__(self):
        self.click_queue = Queue()
        self.click_map = dict()
        self.thread = Thread(target=enqueue_listeners, args=(self,), daemon=True).start()

    def get_click_map(self):
        try:
            while True:
                e = self.click_queue.get_nowait()
                self.click_map[e[0]]=e[1]
        except Empty:
            pass
        return self.click_map
