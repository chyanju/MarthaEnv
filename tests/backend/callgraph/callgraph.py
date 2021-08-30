import base64
import igraph
import subprocess
import sys
import os
import re
import tempfile
import shutil

def decode_base64_graph(path):
    g = igraph.Graph().Read_Ncol(path)
    g.vs['name']=[base64.b64decode(s).decode('utf-8') for s in g.vs['name']]
    return g

def generate_call_graph(apk_path):
    # Get ICC edges
    android_platforms_path = os.path.join(os.environ["ANDROID_SDK_ROOT"],'platforms')
    apk = os.path.basename(apk_path)
    print(f"apk={apk}")
    
    subprocess.run(['docker','build','icc','-t','myic3'])
    
    with tempfile.TemporaryDirectory() as tmpdirname:
        inputdir = os.path.join(tmpdirname,'input')
        outputdir = os.path.join(tmpdirname,'output')
        os.mkdir(inputdir)
        os.mkdir(outputdir)
        shutil.copy(apk_path,inputdir)
        subprocess.run(['docker','run','-it','-v',f'{android_platforms_path}:/srv/android-platforms:ro','-v',f'{inputdir}:/srv/input:ro','-v',f'{outputdir}:/srv/output','myic3:latest','java','-jar','target/ic3-0.2.1-full.jar','-cp','/srv/android-platforms','-a',f'/srv/input/{apk}','-protobuf','/srv/output'])

        assert(len(os.listdir(outputdir))==1)

        icc_path = os.path.join(outputdir,os.listdir(outputdir)[0])
                   
        env = os.environ.copy()
        env['CLASSPATH']=f".:{os.environ['PWD']}/soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar"
        subprocess.run(['javac','AndroidCallgraph.java'],env=env)

        subprocess.run(['java','AndroidCallgraph',apk_path,os.path.join(tmpdirname,'basic.lgl')],env=env)
        subprocess.run(['java','AndroidCallgraph',apk_path,os.path.join(tmpdirname,'icc.lgl'),icc_path],env=env)

        basic_graph = decode_base64_graph(os.path.join(tmpdirname,'basic.lgl'))
        graph = decode_base64_graph(os.path.join(tmpdirname,'icc.lgl'))

    for e in graph.es:
        e["icc"]=True
    for e in basic_graph.es:
        source_name = basic_graph.vs['name'][e.source]
        target_name = basic_graph.vs['name'][e.target]
        eid = graph.get_eid(source_name,target_name) # may not handle multiple edges as desired
        graph.es[eid]["icc"]=False        
    
    for v in graph.vs:
        m = re.match('^<(.*): (.*) (.*)\(.*\)>$',v['name'])
        v['class_sig'] = m.group(1)
        v['class_name'] = v['class_sig'].split('.')[-1]
        v['return_type'] = m.group(2)
        v['func_name'] = m.group(3)
        v['short_name'] = v['class_name']+'.'+v['func_name']

    return graph


if __name__=='__main__':
    if len(sys.argv)>1:
        graph = generate_call_graph(sys.argv[1])
        graph.write_pickle('graph.p')

    graph = igraph.Graph.Read_Pickle('graph.p')

    # graph = graph.subgraph([v.index for v in graph.vs if v['class_name']=='Configs']) # keep only functions from the class Configs
    
    color_dict = {False:'blue',True:'red'}

    plot = igraph.plot(graph,vertex_size=0,bbox=(0,0,1000,1000),edge_color=[color_dict[icc] for icc in graph.es["icc"]], vertex_label=graph.vs['short_name'])
    
    plot.save('graph.png')
