import time
import sys
from martha.apk import Apk
from martha.apk_environment import ApkEnvironment

if len(sys.argv)>1:
    apk_path = sys.argv[1]
else:
    apk_path = "/Users/joseph/Downloads/00a2d33447e572fff3b0f5ecf40e0c53596f6952c94db385be4720ea249cff5b_instrumented.apk"
apk = Apk(apk_path=apk_path)
env = ApkEnvironment(apk=apk)
env.apk.launch_app()
env.apk.clear_logcat()

time.sleep(2)

tmp_state = env.apk.get_whxml()
tmp_action_list = env.apk.get_available_actionable_elements()
env.apk.perform_action(tmp_action_list[0])

