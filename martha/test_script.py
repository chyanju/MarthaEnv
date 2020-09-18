from core import MEnvironment, MState, MAction, MAnalyzer
from uiautomator import Device
import sys

# python3 test_script.py emulator-5554 ../../GATOR/gator-3.8/gator/gator ../../tempodroid/case-studies/ValidRec/app/build/outputs/apk/debug/app-debug.apk

#get device serial num and GATOR path from command-line args
if len(sys.argv) != 4:
    print("Please provide the device serial number, path to the analyzer binary, and path to the target apk as command line arguments")
    exit(1)
serial = sys.argv[1]
analyzer_path = sys.argv[2]
apk_path = sys.argv[3]

#TODO- parameterize serial number that is passed to Device (check active port w adb to get serial num)
# d = Device('emulator-5554')
device = Device(serial)
analyzer = MAnalyzer(analyzer_path, apk_path)

print("Time to test the ANALYZER yeet- constructing graph to pass to env")
apk_graph = analyzer.analyze()
print("AFTER CALL")



print("HERE")
test_env = MEnvironment(device, apk_graph)
print("NOW HERE")

print("Gonna try getting local state:")
curr_state = test_env.get_current_device_state()
print("POST")
if curr_state:
    print("RECEIVED: ", curr_state.to_string())

action_list = test_env.get_available_actions()
if len(action_list) > 0:
    print("OUTSIDE FUNCT, LIST:", action_list)
    print("ATTEMPTING take_action")
    for i in action_list:
        if i._subject.info['text'] == 'SEND':
            print("HERE")
            print("TYPES: ", type(i), type(i._subject), type(i._action))
            test_env.take_action(i)
            break
    print("POST")
    print("Now trying on an object that DNE")
    test_env.take_action(action_list[0])
    print("POST")
else:
    print("Empty list returned, no clicks to take")


