from core import MEnvironment, MState, MAction, MAnalyzer
from uiautomator import Device

#TODO- parameterize serial number that is passed to Device (check active port w adb to get serial num)
d = Device('emulator-5554')
print("HERE")
test_env = MEnvironment(d,None)
print("NOW HERE")
action_list = test_env.get_available_actions()
print("OUTSIDE FUNCT, LIST:", action_list)
print("ATTEMPT")
for i in action_list:
    if i._subject.info['text'] == 'SEND':
        print("HERE")
        print("TYPES: ", type(i), type(i._subject), type(i._action))
        i._action(i._subject)
        break
print("POST")
print("POST")