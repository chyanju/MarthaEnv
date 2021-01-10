#!/usr/bin/env python
# coding: utf-8

# ## Feature Extraction Functions

# In[1]:


from xml.dom import minidom
from collections import defaultdict 
import numpy as np
import editdistance
import random
import time

EMBEDDING_DIM = 8
MAX_TARGET_LENGTH = 30

MAXN_STATE_NODES = 100 # maximum number of state nodes used
MAX_TOKEN_LENGTH = 60 # maximum token length padded to

NODE_KEY_LIST = [ 
    # slot names (keys) of a node to add as features
    "index", # integer
    "bounds", # interval
    "resource-id", "class", # formatted string
]
NODE_KEY_DICT = {NODE_KEY_LIST[i]:i for i in range(len(NODE_KEY_LIST))}

CHAR_LIST = ["<PAD>", "<UNK>"] +list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") +list("abcdefghijklmnopqrstuvwxyz") +list("0123456789") +list("`~!@#$%^&*()_+-={}|[]:;'',.<>/?") +["\\"] + ['"']
CHAR_DICT = defaultdict(
    lambda:CHAR_LIST.index("<UNK>"), 
    {CHAR_LIST[i]:i for i in range(len(CHAR_LIST))}
)

PADDING_NODE_VECTOR = [ [CHAR_DICT["<PAD>"] for _ in range(MAX_TOKEN_LENGTH)] for _ in range(len(NODE_KEY_LIST))]


# ## Pipeline Utils

# In[2]:


def action_filter(arg_alist):
    # remove system Back/Home gui elements
#     return arg_alist
    tmp0 = [
        arg_alist[i] 
        for i in range(len(arg_alist)) 
        if "com.android.systemui" not in arg_alist[i].attributes["resource-id"]
    ]
#     print("actions: {}".format(tmp0))
    return tmp0
#     tmp1 = [
#         tmp0[i] 
#         for i in range(len(tmp0)) 
#         if "android.widget.EditText" not in tmp0[i].attributes["class"]
#     ]
#     return tmp1


# In[3]:


def rollout(arg_config):
    
    for ep in range(arg_config["n_episodes"]):
        print("# episode {}".format(ep))
        
        # reset
        arg_config["environment"].launch_app()
        
        rollout_action_ids = []

        for i in range(arg_config["maxn_steps"]):

            i_observation = arg_config["environment"].get_current_state()
            i_ids = action_filter(
                arg_config["environment"].get_available_actionable_elements(i_observation)
            )

            # explore
            selected_action_id = random.choice(list(range(len(i_ids))))
            rollout_action_ids.append(selected_action_id) # action is action_id in this case
            arg_config["environment"].perform_action(i_ids[selected_action_id])
            rlist = arg_config["environment"].get_reached_goal_states("train")
            rlist = [p for p in rlist if p != '<com.zoffcc.applications.aagtl.ImageManager: void DownloadFromUrl(java.lang.String,java.lang.String)> : 11'] # 4s done
            if len(rlist)>0:
                # goal state!
                # input("PAUSE: goal state!")
                # break
                print("# rlist: {}".format(rlist))
                print("# goal state!")
                return
                
        print("  steps={}, actions={}".format(i, rollout_action_ids))


# ## set up environment

# In[4]:


from main import *

CURR_DIR = os.path.dirname(os.getcwd())
OUTPUT_DIR = os.path.join(CURR_DIR, "results")

args = {
#     "path": "../test/com.github.cetoolbox_11/app_simple0.apk",
    "path": "/home/priyanka/research/projects/goal_input/Wordpress_394/Wordpress_394.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/com.zoffcc.applications.aagtl_31/com.zoffcc.applications.aagtl_31.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/Translate/Translate.apk",
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
apk.clean_logcat()


# In[5]:


config = {
    "environment": apk,
    "maxn_steps": 4,
    "n_episodes": 100000,
}
start_time = time.time()
rollout(config)
end_time = time.time()
print("# total time: {}".format(end_time-start_time))


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




