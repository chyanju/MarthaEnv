#!/usr/bin/env python
# coding: utf-8

# ## Feature Extraction Functions

# In[1]:


from xml.dom import minidom
from collections import defaultdict 
import numpy as np
import editdistance
import random

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


# In[2]:


# specific method for target encoding
# similar to get_node_vector but without the node assumption
# arg_node is a list of strings
def get_sentence_vector(arg_sent):
    sent_vector = []
    for j in range(len(arg_sent)):
        chars_j = list(arg_sent[j])
        # get the indices for every char
        inds_j = [CHAR_DICT[chars_j[k]] for k in range( min(MAX_TOKEN_LENGTH,len(chars_j)) )]
        # pad the inds
        inds_j += [CHAR_DICT["<PAD>"]] * ( MAX_TOKEN_LENGTH-len(inds_j) )
        sent_vector.append(inds_j)
    return sent_vector

# arg_node is a gui element object
# (element from action list)
def get_element_vector(arg_elem):
    elem_vector = []
    for j in range(len(NODE_KEY_LIST)):
        key_j = NODE_KEY_LIST[j]
        str_j = str(arg_elem.attributes[key_j])
        chars_j = list(str_j)
        # get the indices for every char
        inds_j = [CHAR_DICT[chars_j[k]] for k in range( min(MAX_TOKEN_LENGTH,len(chars_j)) )]
        # pad the inds
        inds_j += [CHAR_DICT["<PAD>"]] * ( MAX_TOKEN_LENGTH-len(inds_j) )
        elem_vector.append(inds_j)
    return elem_vector

# arg_node is a ui element object
# (node from state)
def get_node_vector(arg_node):
    node_vector = []
    for j in range(len(NODE_KEY_LIST)):
        key_j = NODE_KEY_LIST[j]
        str_j = str(arg_node.attributes[key_j].value)
        chars_j = list(str_j)
        # get the indices for every char
        inds_j = [CHAR_DICT[chars_j[k]] for k in range( min(MAX_TOKEN_LENGTH,len(chars_j)) )]
        # pad the inds
        inds_j += [CHAR_DICT["<PAD>"]] * ( MAX_TOKEN_LENGTH-len(inds_j) )
        node_vector.append(inds_j)
    return node_vector

# a state here is a windows hierarchy string
def get_state_matrix(arg_wh):
    state_nodes = minidom.parseString(arg_wh).getElementsByTagName('node')
    state_matrix = []
    for i in range( min(MAXN_STATE_NODES,len(state_nodes)) ):
        state_vector = []
        node_i = state_nodes[i]
        node_vector_i = get_node_vector(node_i)
        state_matrix.append(node_vector_i)
    # pad the state matrix
    state_matrix += [PADDING_NODE_VECTOR] * ( MAXN_STATE_NODES-len(state_matrix) )
    return state_matrix


# ## Neural Agent
# - UniversalTokenEncoder: relu
# - StateEncoder: relu
# - TargetEncoder: relu
# - ActionEncoder: sigmoid

# In[3]:


import torch
import numpy as np
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print("device: {}".format(device))
print("torch version: {}".format(torch.__version__))


# In[4]:


class UniversalTokenEncoder(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(UniversalTokenEncoder, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.char_embedding = nn.Embedding(
            num_embeddings=len(CHAR_LIST),
            embedding_dim=arg_embedding_dim,
        )
        self.n_kernels = [10, 10, 10]
        self.kernel_sizes = [1, 2, 3]
        self.convs = nn.ModuleList([
            nn.Conv1d(
                in_channels=arg_embedding_dim, 
                out_channels=self.n_kernels[i], 
                kernel_size=self.kernel_sizes[i], 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.pools = nn.ModuleList([
            nn.MaxPool1d(MAX_TOKEN_LENGTH+1-self.kernel_sizes[i], padding=0)
            for i in range(len(self.kernel_sizes))
        ])
        self.linear = nn.Linear(sum(self.n_kernels), arg_embedding_dim)
        
    # input a batch of sequences (high-dimensional)
    # arg_seqs: (B=1, ??, len(NODE_KEY_LIST) or MAX_TARGET_LENGTH, MAX_TOKEN_LENGTH)
    # ??=MAXN_STATE_NODES if encoding state matrix
    # ??=1 if encoding the target
    # ??=others if encoding an action list
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        # tmp_dim0 = B * tmpn_nodes * len(NODE_KEY_LIST)
        tmp_dim0 = B * tmpn_nodes * arg_seqs.shape[2]
        assert B==1
        # first fold the first 3 dimensions
        tmp0 = arg_seqs.view(tmp_dim0, MAX_TOKEN_LENGTH) # (dim0, MAX_TOKEN_LENGTH)
        tmp1 = self.char_embedding(tmp0) # (dim0, MAX_TOKEN_LENGTH, embedding_dim)
        tmp2 = tmp1.transpose(1,2) # channel goes first for conv, (dim0, embedding_dim, MAX_TOKEN_LENGTH)
        # (dim0, n_kernels, MAX_TOKEN_LENGTH-i)
        tmp3s = [
            F.relu(self.convs[i](tmp2))
            for i in range(len(self.convs))
        ]
        # (dim0, n_kernels, 1)
        tmp4s = [
            self.pools[i](tmp3s[i])
            for i in range(len(tmp3s))
        ]
        # (dim0, n_kernels)
        tmp5s = [
            tmp4s[i].view(tmp_dim0, self.n_kernels[i])
            for i in range(len(tmp4s))
        ]
        tmp6 = torch.cat(tmp5s, 1) # (dim0, sum(n_kernels))
        tmp7 = F.relu(self.linear(tmp6)) # (dim0, embedding_dim)
        # unfold back to original shape
        # which is (B=1, ??={MAXN_STATE_NODES,1,others}, len(NODE_KEY_LIST) or MAX_TARGET_LENGTH, embedding_dim)
        # tmp8 = tmp7.view(B, tmpn_nodes, len(NODE_KEY_LIST), self.embedding_dim)
        tmp8 = tmp7.view(B, tmpn_nodes, arg_seqs.shape[2], self.embedding_dim)
        return tmp8
        


# In[5]:


class StateEncoder(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(StateEncoder, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.n_kernels = [10, 10, 10]
        self.kernel_sizes = [(1,len(NODE_KEY_LIST)), (2,len(NODE_KEY_LIST)), (3,len(NODE_KEY_LIST))]
        self.convs = nn.ModuleList([
            nn.Conv2d(
                in_channels=arg_embedding_dim, 
                out_channels=self.n_kernels[i], 
                kernel_size=self.kernel_sizes[i], 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.pools = nn.ModuleList([
            nn.MaxPool2d(
                kernel_size=(
                    MAXN_STATE_NODES+1-self.kernel_sizes[i][0],
                    len(NODE_KEY_LIST)+1-self.kernel_sizes[i][1],
                ), 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.linear = nn.Linear(sum(self.n_kernels), arg_embedding_dim)
        
    # input a batch of sequences (high-dimensional)
    # arg_seqs: (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
    # ??=MAXN_STATE_NODES since it's encoding state matrix
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        assert B==1
        assert tmpn_nodes==MAXN_STATE_NODES
        # permute for conv
        tmp0 = arg_seqs.permute(0,3,1,2) # (B=1, embedding_dim, ??, len(NODE_KEY_LIST))
        # (B=1, n_kernels, ??-i, len(NODE_KEY_LIST)-i)
        tmp1s = [
            F.relu(self.convs[i](tmp0))
            for i in range(len(self.convs))
        ]
        # (B=1, n_kernels, 1, 1)
        tmp2s = [
            self.pools[i](tmp1s[i])
            for i in range(len(tmp1s))
        ]
        # (B=1, n_kernels)
        tmp3s = [
            tmp2s[i].view(B, self.n_kernels[i])
            for i in range(len(tmp2s))
        ]
        tmp4 = torch.cat(tmp3s, 1) # (B, sum(n_kernels))
        tmp5 = F.relu(self.linear(tmp4)) # (B, embedding_dim)
        return tmp5


# In[6]:


class TargetEncoder(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(TargetEncoder, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.n_kernels = [10, 10, 10]
        self.kernel_sizes = [1, 2, 3]
        self.convs = nn.ModuleList([
            nn.Conv1d(
                in_channels=arg_embedding_dim, 
                out_channels=self.n_kernels[i], 
                kernel_size=self.kernel_sizes[i], 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.pools = nn.ModuleList([
            nn.MaxPool1d(
                kernel_size=(
                    MAX_TARGET_LENGTH+1-self.kernel_sizes[i],
                ), 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.linear = nn.Linear(sum(self.n_kernels), arg_embedding_dim)
        
    # input a batch of sequences (high-dimensional)
    # arg_seqs: (B=1, ??, MAX_TARGET_LENGTH, embedding_dim)
    # ??=1 since it's encoding a target
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        tmp_dim0 = B * tmpn_nodes
        assert B==1
        assert tmpn_nodes==1
        # action nodes are encoded separately, so change the view first
        # (dim0, MAX_TARGET_LENGTH, embedding_dim)
        # -> (dim0, embedding_dim, len(NODE_KEY_LIST))
        tmp0 = arg_seqs.view(tmp_dim0, MAX_TARGET_LENGTH, self.embedding_dim).transpose(1,2)
        # (dim0, n_kernels, MAX_TARGET_LENGTH-i)
        tmp1s = [
            F.relu(self.convs[i](tmp0))
            for i in range(len(self.convs))
        ]
        # (dim0, n_kernels, 1)
        tmp2s = [
            self.pools[i](tmp1s[i])
            for i in range(len(tmp1s))
        ]
        # (dim0, n_kernels)
        tmp3s = [
            tmp2s[i].view(tmp_dim0, self.n_kernels[i])
            for i in range(len(tmp2s))
        ]
        tmp4 = torch.cat(tmp3s, 1) # (dim0, sum(n_kernels))
        tmp5 = F.relu(self.linear(tmp4)) # (dim0, embedding_dim)
        tmp6 = tmp5.view(B, tmpn_nodes, self.embedding_dim) # (B=1, ??, embedding_dim)
        return tmp6


# In[7]:


# note: ActionEncoder is actually encoding a list of actions
#       not a single action
class ActionEncoder(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(ActionEncoder, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.n_kernels = [10, 10, 10]
        self.kernel_sizes = [1, 2, 3]
        self.convs = nn.ModuleList([
            nn.Conv1d(
                in_channels=arg_embedding_dim, 
                out_channels=self.n_kernels[i], 
                kernel_size=self.kernel_sizes[i], 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.pools = nn.ModuleList([
            nn.MaxPool1d(
                kernel_size=(
                    len(NODE_KEY_LIST)+1-self.kernel_sizes[i],
                ), 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.linear_w = nn.Linear(sum(self.n_kernels), arg_embedding_dim) # weight
        self.linear_b = nn.Linear(sum(self.n_kernels), 1) # bias
        
    # input a batch of sequences (high-dimensional)
    # arg_seqs: (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
    # ??=others since it's encoding an action list
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        tmp_dim0 = B * tmpn_nodes
        assert B==1
        # action nodes are encoded separately, so change the view first
        # (dim0, len(NODE_KEY_LIST), embedding_dim)
        # -> (dim0, embedding_dim, len(NODE_KEY_LIST))
        tmp0 = arg_seqs.view(tmp_dim0, len(NODE_KEY_LIST), self.embedding_dim).transpose(1,2)
        # (dim0, n_kernels, len(NODE_KEY_LIST)-i)
        tmp1s = [
            F.relu(self.convs[i](tmp0))
            for i in range(len(self.convs))
        ]
        # (dim0, n_kernels, 1)
        tmp2s = [
            self.pools[i](tmp1s[i])
            for i in range(len(tmp1s))
        ]
        # (dim0, n_kernels)
        tmp3s = [
            tmp2s[i].view(tmp_dim0, self.n_kernels[i])
            for i in range(len(tmp2s))
        ]
        tmp4 = torch.cat(tmp3s, 1) # (dim0, sum(n_kernels))
        tmp5_w = F.relu(self.linear_w(tmp4)) # (dim0, embedding_dim)
        tmp5_b = F.relu(self.linear_b(tmp4)) # (dim0, embedding_dim)
        tmp6_w = tmp5_w.view(B, tmpn_nodes, self.embedding_dim) # (B=1, ??, embedding_dim)
        tmp6_b = tmp5_b.view(B, tmpn_nodes, 1) # (B=1, ??, 1)
        return tmp6_w, tmp6_b


# In[8]:


class NeuralAgent(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(NeuralAgent, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.universal_token_encoder = UniversalTokenEncoder(arg_embedding_dim)
        self.state_encoder = StateEncoder(arg_embedding_dim)
        self.target_encoder = TargetEncoder(arg_embedding_dim)
        self.action_encoder = ActionEncoder(arg_embedding_dim)
        
        self.hidden0 = nn.Linear(arg_embedding_dim*2, arg_embedding_dim)
        
    # arg_state: (B=1, ??=MAXN_STATE_NODES, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
    # arg_target: (B=1, ??=1, MAX_TARGET_LENGTH, MAX_TOKEN_LENGTH)
    def compute_preference_matrix(self, arg_state, arg_target):
        B_state = arg_state.shape[0]
        B_target = arg_target.shape[0]
        assert B_state==1
        assert B_target==1
        
        # fixme: only support 1 target at a time
        n_targets = arg_target.shape[1]
        assert n_targets==1 
        
        tmp0_state = self.universal_token_encoder(arg_state) # (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
        tmp0_target = self.universal_token_encoder(arg_target) # (B=1, ??, MAX_TARGET_LENGTH, embedding_dim)
        tmp1_state = self.state_encoder(tmp0_state) # (B=1, embedding_dim)
        tmp1_target = self.target_encoder(tmp0_target) # (B=1, ??, embedding_dim)
        tmp2_state = tmp1_state
        
        # fixme: only support 1 target at a time
        tmp2_target = tmp1_target.view(B_target, self.embedding_dim) # (B=1, embedding_dim)
        
        tmp3 = torch.cat([tmp2_state, tmp2_target], 1) # (B=1, embedding_dim * 2)
        tmp4 = torch.sigmoid(self.hidden0(tmp3)) # (B=1, embedding_dim)
        return tmp4

    # arg_action: (B=1, ??=others, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
    def compute_action_matrix(self, arg_action):
        B = arg_action.shape[0]
        tmp0 = self.universal_token_encoder(arg_action) # (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
        tmp1_w, tmp1_b = self.action_encoder(tmp0) # (B=1, ??, embedding_dim)
        return tmp1_w, tmp1_b
    
    def compute_similarity_matrix(self, arg_pref, arg_w, arg_b):
        # arg_pref: (B=1, embedding_dim)
        # arg_w: (B=1, ??, embedding_dim)
        # arg_b: (B=1, ??, 1)
        B = arg_pref.shape[0]
        A = arg_w.shape[1]
        assert B==1
        assert B==arg_w.shape[0]
        assert B==arg_b.shape[0]
        assert A==arg_b.shape[1]
        tmp0 = arg_pref.view((B, self.embedding_dim, 1)) # (B=1, embedding_dim, 1)
        tmp1 = torch.matmul(arg_w, tmp0) # (B=1, ??, 1)
        tmp2 = torch.add(tmp1, arg_b)
        tmp3 = tmp2.view((B,A)) # (B=1, ??)
        tmp4 = F.log_softmax(tmp3, dim=1)
        return tmp4


# ## Pipeline Utils

# In[9]:


def action_filter(arg_alist):
    # remove system Back/Home gui elements
    tmp0 = [
        arg_alist[i] 
        for i in range(len(arg_alist)) 
        if "com.android.systemui" not in arg_alist[i].attributes["resource-id"]
    ]
    return tmp0
#     tmp1 = [
#         tmp0[i] 
#         for i in range(len(tmp0)) 
#         if "android.widget.EditText" not in tmp0[i].attributes["class"]
#     ]
#     return tmp1


# In[10]:


def rollout(arg_config):
    batch_loss = 0.
    
    for ep in range(arg_config["n_episodes"]):
        print("# episode {}".format(ep))
        epsilon = arg_config["epsilon"](ep)
        print("  epsilon={}".format(epsilon))
        
        # reset
        arg_config["environment"].launch_app()
        
        rollout_outputs = []
        rollout_actions = []
        rollout_action_ids = []
        rollout_rewards = []

        for i in range(arg_config["maxn_steps"]):
            
            # should wrap [] to make B=1
            # (B=1, ??=MAXN_STATE_NODES, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
            i_observation = arg_config["environment"].get_current_state()
            inp_observation = np.asarray([get_state_matrix(i_observation)])
            its_observation = Variable(torch.tensor(inp_observation, dtype=torch.long).to(device))
            
            # (B=1, ??=others, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
            # i_ids = arg_config["environment"].get_available_actionable_elements(i_observation)
            i_ids = action_filter(
                arg_config["environment"].get_available_actionable_elements(i_observation)
            )
            inp_ids = np.asarray([[
                get_element_vector(i_ids[j])
                for j in range(len(i_ids))
            ]])
            its_ids = Variable(torch.tensor(inp_ids, dtype=torch.long).to(device))
            
            # (B=1, ??=1, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
            inp_target = np.asarray([[
                get_sentence_vector(arg_config["target"])
            ]])
            its_target = Variable(torch.tensor(inp_target, dtype=torch.long).to(device))
            
            arg_config["agent"].train()
            its_preference_matrix = arg_config["agent"].compute_preference_matrix(its_observation, its_target) # (B=1, embedding_dim)
            its_w, its_b = arg_config["agent"].compute_action_matrix(its_ids) # (B=1, ??, embedding_dim)
            # compute similarity
            # (B=1, ??)
            its_sim = arg_config["agent"].compute_similarity_matrix(
                its_preference_matrix,
                its_w, its_b
            )
            
            i_output = its_sim.flatten().exp().tolist() # (??,)

            if random.random()<epsilon:
                # explore
                selected_action_id = random.choice(list(range(len(i_output))))
            else:
                # exploit
                selected_action_id = np.argmax(i_output)

            # keep track
            rollout_outputs.append(its_sim)
            rollout_actions.append(i_ids[selected_action_id])
            rollout_action_ids.append(selected_action_id) # action is action_id in this case
            
            arg_config["environment"].perform_action(i_ids[selected_action_id])
            i_reward = None
            rlist = arg_config["environment"].get_reached_goal_states("train")
            if len(rlist)>0:
                # goal state!
                i_reward = +1.0
                rollout_rewards.append(i_reward)
                break
            else:
                if i==arg_config["maxn_steps"]-1:
                    i_reward = -0.1
                    # i_reward = +0.01
                    # i_reward = 0.0
                else:
                    ja = rollout_actions[-1].attributes
                    qa = [p.attributes for p in rollout_actions[:-1]]
                    if ja in qa:
                        i_reward = -0.1
                        # i_reward = +0.0001
                        # i_reward = 0.0
                    else:
                        # check for partial rewards
                        # fixme: manually assigned, which should have been the job of static analysis
                        j_observation = arg_config["environment"].get_current_state()
                        if arg_config["partial_target"] in j_observation:
                            # reward adjustment: if duplicate action, reduce!
                            i_reward = +1.0
                        elif "∞" in j_observation:
                            # reward adjustment: if duplicate action, reduce!
                            i_reward = +1.0
                        else:
                            # i_reward = 0.01
                            i_reward = 0.0
                rollout_rewards.append(i_reward)
                
        # reward-length penalization
        rollout_rewards = [p+(arg_config["maxn_steps"]-len(rollout_rewards)) for p in rollout_rewards]
        print("  steps={}, rewards={}, actions={}".format(i, rollout_rewards, rollout_action_ids))
        rollout_loss = []
        for i in range(len(rollout_outputs)):
            current_return = 0.
            for j in range(i,len(rollout_outputs)):
                df = 0.9**(j-i)
                current_return += df * rollout_rewards[j]
            rollout_loss.append( current_return * (-rollout_outputs[i][0][rollout_action_ids[i]]) )

        ep_loss = sum(rollout_loss)
        batch_loss += ep_loss
        if (ep+1)%arg_config["batch_size"]==0:
            print("  update policy")
            arg_config["optimizer"].zero_grad()
            batch_loss = batch_loss / arg_config["batch_size"]
            batch_loss.backward()
            arg_config["optimizer"].step()
            batch_loss = 0.


# ## set up environment

# In[11]:


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
apk.clean_logcat()


# In[ ]:


neural_agent = NeuralAgent(EMBEDDING_DIM).to(device)
# optimizer = torch.optim.SGD(agent.parameters(), lr=0.01)
# optimizer = torch.optim.Adam(agent.parameters(), lr=0.01)
optimizer = torch.optim.RMSprop(neural_agent.parameters(), lr=0.01)
target_str = "<com.github.cetoolbox.fragments.tabs.FlowrateActivity: void onItemSelected(android.widget.AdapterView,android.view.View,int,long)> : null"
target = target_str.replace("<","#").replace(">","#").replace(".","#").replace(":","#")                   .replace("(","#").replace(")","#").replace(",","#").replace(" ","#").split("#")
target = [p for p in target if len(p.strip())>0]
target += [[""]] * ( MAX_TARGET_LENGTH-len(target) )
partial_target = """
text="FLOWRATE" resource-id="android:id/title" class="android.widget.TextView" package="com.github.cetoolbox" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="true"
""".strip()
config = {
    "environment": apk,
    "agent": neural_agent,
    "optimizer": optimizer,
    "maxn_steps": 4,
    "n_episodes": 100000,
    "epsilon": lambda x: max(0.05, 0.95-x/160*0.95), # explore prob
    "batch_size": 4,
    "target": target,
    "partial_target": partial_target,
}
rollout(config)


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




