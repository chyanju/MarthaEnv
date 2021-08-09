import base64
import igraph
import subprocess
import sys
import os

def get_call_graph(apk_path):
    env = os.environ.copy()
    env['CLASSPATH']=f".:{os.environ['PWD']}/soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar"
    subprocess.run(['javac','AndroidCallgraph.java'],env=env)
    subprocess.run(['java','AndroidCallgraph',apk_path],env=env)
    g = igraph.Graph().Read_Ncol("base64.lgl")
    g.vs["name"]=[base64.b64decode(s).decode('utf-8') for s in g.vs["name"]]

    return g

if __name__=='__main__':
    get_call_graph(sys.argv[1])
