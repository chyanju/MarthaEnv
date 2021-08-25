import base64
import igraph
import subprocess
import sys
import os

def decode_base64_graph(path):
    g = igraph.Graph().Read_Ncol(path)
    g.vs["name"]=[base64.b64decode(s).decode('utf-8') for s in g.vs["name"]]
    return g

def generate_call_graph(apk_path):
    # Get ICC edges
    android_platforms_path = os.path.join(os.environ["ANDROID_SDK_ROOT"],'platforms')
    apk = os.path.basename(apk_path)
    print(f"apk={apk}")
    
    subprocess.run(['docker','build','icc','-t','myic3'])
    subprocess.run(['mkdir','input/'])
    subprocess.run(['rm','-rf','output/'])
    subprocess.run(['mkdir','output/'])
    subprocess.run(['cp',apk_path,'input'])
    subprocess.run(['docker','run','-it','-v',f'{android_platforms_path}:/srv/android-platforms:ro','-v',f'{os.getcwd()}/input:/srv/input:ro','-v',f'{os.getcwd()}/output:/srv/output','myic3:latest','java','-jar','target/ic3-0.2.1-full.jar','-cp','/srv/android-platforms','-a',f'/srv/input/{apk}','-protobuf','/srv/output'])

    assert(len(os.listdir('output'))==1)

    icc_path = os.path.join('output',os.listdir('output')[0])
                   
    env = os.environ.copy()
    env['CLASSPATH']=f".:{os.environ['PWD']}/soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar"
    subprocess.run(['javac','AndroidCallgraph.java'],env=env)
    subprocess.run(['java','AndroidCallgraph',apk_path,'basic.lgl'],env=env)
    subprocess.run(['java','AndroidCallgraph',apk_path,'icc.lgl',icc_path],env=env)

#If apk_path is None, use lgl files from last run
def get_call_graph(apk_path=None):
    if apk_path:
        generate_call_graph(apk_path)
    basic_graph = decode_base64_graph("basic.lgl")
    graph = decode_base64_graph("icc.lgl")

    for e in graph.es:
        e["icc"]=True
    for e in basic_graph.es:
        source_name = basic_graph.vs['name'][e.source]
        target_name = basic_graph.vs['name'][e.target]
        eid = graph.get_eid(source_name,target_name) # may not handle multiple edges as desired
        graph.es[eid]["icc"]=False        

    return graph


def locate_nodes(g, sigs):
	return g.subgraph(sigs)

if __name__=='__main__':
    if len(sys.argv)>1:
        graph = get_call_graph(sys.argv[1])
    else:
        graph = get_call_graph()
    color_dict = {False:'blue',True:'red'}
    igraph.plot(graph,vertex_size=0,bbox=(0,0,1000,1000),edge_color=[color_dict[icc] for icc in graph.es["icc"]])
