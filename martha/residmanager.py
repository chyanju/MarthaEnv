import subprocess
import sys
import os
import re

class ResourceIDManager:
    def __init__(self,apk_path,aapt_path=None):
        if aapt_path is None:
            aapt_path = os.path.join(os.environ["ANDROID_SDK_ROOT"],'build-tools','31.0.0','aapt')
        lines = subprocess.check_output([aapt_path,'dump','resources',apk_path]).decode('utf-8')
        #print(lines)
        self.id_to_name_map = {}
        self.name_to_id_map = {}
        for line in lines.splitlines():
            m = re.match(r' *spec resource 0x([0-9a-fA-F]+) (\S+):.*',line)
            if not m:
                m = re.match(r' *resource 0x([0-9a-fA-F]+) (\S+):.*',line)
            if not m:
                # Failed to parse. Probably section heading
                continue
                
            res_id = int(m.group(1),16) # ID is in hex
            res_name = m.group(2)
            #print(res_id,res_name)
            self.id_to_name_map[res_id] = res_name
            self.name_to_id_map[res_name] = res_id
                    
    def id_to_name(self,res_id):
        return self.id_to_name_map[res_id]
    def name_to_id(self,res_name):
        return self.name_to_id_map[res_name]

    
if __name__=='__main__':
    if len(sys.argv)<2:
        print(f'Usage: {sys.argv[0]} path-to-apk')
        exit()

    resource_id_manager = ResourceIDManager(sys.argv[1])
