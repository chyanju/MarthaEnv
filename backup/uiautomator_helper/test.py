from exp2_random import *
import time
import igraph

cg = igraph.Graph.Read_Pickle('../../tests/backend/callgraph/graph.p')


from residmanager import ResourceIDManager 

residmanager = ResourceIDManager('../../tests/backend/instrument/aligned.apk')

from logcatwatcher import LogcatWatcher
watcher = LogcatWatcher(residmanager)

        
def dump_cg():
    for e in cg.es:
        source_name = cg.vs['name'][e.source]
        target_name = cg.vs['name'][e.target]
        print(source_name,target_name)

def dump():
    click_map = watcher.get_click_map()
    print("Click map:")
    print(click_map)
    print("GUI elements:")
    for e in apk_obj.get_available_actionable_elements(apk_obj.get_current_state()):
        #print(f"{e.attributes}")
        if e.resource_id in click_map:
            funct_name = click_map[e.resource_id]
            try:
                func = cg.vs['name'].index(funct_name)
                #print('Lookup Success')
            except:
                func = '(Error)'
                #print(f'Lookup Failed: {funct_name} in {cg.vs["name"]}')
        else:
            func = '(None)'
        print(f"{e.resource_id} => {func}")

if __name__ == '__main__':
    while True:
        time.sleep(5)
        dump()
        print()
