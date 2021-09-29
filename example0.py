import time
import sys
from martha.apk import Apk
from martha.apk_environment import ApkEnvironment
import os

apk_path = f"{os.environ['HOME']}/Downloads/00a2d33447e572fff3b0f5ecf40e0c53596f6952c94db385be4720ea249cff5b_instrumented.apk"
apk = Apk(apk_path=apk_path)
env = ApkEnvironment(apk=apk)
env.apk.launch_app()
env.apk.clear_logcat()

time.sleep(2)

tmp_state = env.apk.get_whxml()
tmp_action_list = env.apk.get_available_actionable_elements()

print(tmp_action_list)

for elem in tmp_action_list:
    cg_node = env.get_node_for_action(elem)
    print(f'{elem.resource_id} => vertex {cg_node}')
    


env.apk.perform_action(tmp_action_list[1])
