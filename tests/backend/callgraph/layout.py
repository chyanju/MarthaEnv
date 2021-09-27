import subprocess
import sys
import os
import re
import pickle

def get_layout_onclicks(apk_path):
    apk = os.path.basename(apk_path)
    
    env = os.environ.copy()
    env['CLASSPATH']=f".:{os.environ['PWD']}/soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar"
    subprocess.run(['javac','AndroidLayoutOnClick.java'],env=env)
    
    lines = subprocess.check_output(['java','AndroidLayoutOnClick',apk_path],env=env).decode('utf-8')

    table = {}
    
    for line in lines.splitlines():
        m = re.match(r'^(\S+)$',line)
        if m:
            xml = m.group(1)
            table[xml] = {}
            continue
        m = re.match(r'^(\S+) (\S+) (\S+)$',line)
        if m:
            xml = m.group(1)
            buttonid = m.group(2)
            callbackname = m.group(3)
            table[xml][int(buttonid)]=callbackname
    return table
        


if __name__=='__main__':
    if len(sys.argv)<2:
        print(f'Usage: {sys.argv[0]} path-to-apk')
        exit()

    table = get_layout_onclicks(sys.argv[1])
    
    print(table)
    
    with open('onclicks.p','wb') as f:
        pickle.dump(table,f)
