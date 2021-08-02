#!/usr/bin/env python
# coding: utf-8

# ## Pipeline Utils

# In[1]:


def action_filter(arg_alist):
    # remove system Back/Home gui elements
    tmp0 = [
        arg_alist[i] 
        for i in range(len(arg_alist)) 
        if "com.android.systemui" not in arg_alist[i].attributes["resource-id"]
    ]
    tmp1 = [
        tmp0[i] 
        for i in range(len(tmp0)) 
        if "android.widget.EditText" not in tmp0[i].attributes["class"]
    ]
    return tmp1


# ## set up environment

# In[2]:


from main import *

CURR_DIR = os.path.dirname(os.getcwd())
OUTPUT_DIR = os.path.join(CURR_DIR, "results")

args = {
    "path": "../test/com.github.cetoolbox_11/app_simple0.apk",
    "output": "../results/",
}

if args["path"] is not None:
    pyaxmlparser_apk = APK(args["path"])
    apk_base_name = os.path.splitext(os.path.basename(args["path"]))[0]

else:
    parser.print_usage()

if args["output"] is not None:
    OUTPUT_DIR = args["output"]

output_dir = os.path.join(OUTPUT_DIR, apk_base_name)

if os.path.exists(output_dir):
    rmtree(output_dir)

if not os.path.exists(output_dir):
    os.mkdir(output_dir)

# Setting the path for log file
log_path = os.path.join(output_dir, 'analysis.log')
log = init_logging('analyzer.%s' % apk_base_name, log_path, file_mode='w', console=True)

# Record analysis start time
now = datetime.datetime.now()
analysis_start_time = now.strftime(DATE_FORMAT)
info('Analysis started at: %s' % analysis_start_time)
start_time = time.time()

# Get the serial for the device attached to ADB
device_serial = get_device_serial(log)

if device_serial is None:
    log.warning("Device is not connected!")
    sys.exit(1)

# Initialize the uiautomator device object using the device serial
uiautomator_device = u2.connect(device_serial)
run_adb_as_root(log)
apk = Apk(args["path"], uiautomator_device, log)
apk.launch_app()
# to track some goal state at startup, you don't have to do this
# apk.clean_logcat()


# In[ ]:





# In[ ]:





# In[ ]:





# In[3]:


print("### 1st ###")
tmp0 = action_filter(apk.get_available_actionable_elements(apk.get_current_state()))
apk.perform_action(tmp0[-3])
print(apk.get_reached_goal_states("train"))


# In[4]:

print("### 2nd ###")
tmp0 = action_filter(apk.get_available_actionable_elements(apk.get_current_state()))
apk.perform_action(tmp0[2])
print(apk.get_reached_goal_states("train"))


# In[5]:

print("### 3rd ###")
tmp0 = action_filter(apk.get_available_actionable_elements(apk.get_current_state()))
apk.perform_action(tmp0[0])
print(apk.get_reached_goal_states("train"))


# In[ ]:





# In[ ]:




