import subprocess
from threading import Thread
from queue import Queue, Empty
import re
import pickle

from .apk import Apk

def enqueue_listeners(watcher):
    p = subprocess.Popen(["adb","logcat","-e","MARTHA"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    for line in p.stdout:
        m = re.match('.*MARTHA: setOnClickListener (.*) to (.*)\n',line.decode("utf-8"))
        if m:
            name = m.group(1)
            callback_class = m.group(2)
            watcher.click_queue.put((name,f'<{callback_class}: void onClick(android.view.View)>'))
            continue

        m = re.match('.*MARTHA: setContentView (.*) to (.*):(.*)\n',line.decode("utf-8"))
        if m:
            activity = m.group(1)
            app = m.group(2)
            xml = m.group(3)
            print(activity,xml)
            if f'res/{xml}.xml' in watcher.layout_onclicks:
                print(xml,'loaded')
                for res_id, funct_name in watcher.layout_onclicks[f'res/{xml}.xml'].items():
                    print(res_id,funct_name)
                    try:
                        res_name = apk.resource_id_to_name[str(res_id)]
                        print(res_id,'=',res_name,funct_name)
                        callback = f'<{activity}: void {funct_name}(android.view.View)>'
                        watcher.click_queue.put((res_name,callback))
                    except:
                        print(f'Failed to decode resource ID {res_id}',file=sys.stderr)
                    
            else:
                print('ERROR: ',xml,'not found in',watcher.layout_onclicks)
        else:
            pass
            #print(line)

class LogcatWatcher:
    def __init__(self,apk: Apk,layout_onclicks):
        self.click_queue = Queue()
        self.click_map = dict()
        self.layout_onclicks = layout_onclicks
        self.thread = Thread(target=enqueue_listeners, args=(self,), daemon=True).start()
        self.apk = apk

    def get_click_map(self):
        try:
            while True:
                e = self.click_queue.get_nowait()
                self.click_map[e[0]]=e[1]
        except Empty:
            pass
        return self.click_map
