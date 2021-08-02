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

EMBEDDING_DIM = 16

MAXN_STATE_NODES = 400 # maximum number of state nodes used
MAX_TOKEN_LENGTH = 20 # maximum token length padded to

NODE_KEY_LIST = [ 
    # slot names (keys) of a node to add as features
    "index", # integer
    "checkable", "checked", "clickable", "enabled", "focusable", "focused", # boolean
    "scrollable", "long-clickable", "password", "selected", "visible-to-user", # boolean
    "bounds", # interval
    "content-desc", # string
    "resource-id", "class", "package", # formatted string
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
    # arg_seqs: (B=1, ??, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
    # ??=MAXN_STATE_NODES if encoding state matrix
    # ??=1 if encoding the target
    # ??=others if encoding an action list
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        tmp_dim0 = B * tmpn_nodes * len(NODE_KEY_LIST)
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
        # which is (B=1, ??={MAXN_STATE_NODES,1,others}, len(NODE_KEY_LIST), embedding_dim)
        tmp8 = tmp7.view(B, tmpn_nodes, len(NODE_KEY_LIST), self.embedding_dim)
        return tmp8
        


# In[5]:


class StateEncoder(nn.Module):
    def __init__(self, arg_embedding_dim):
        super(StateEncoder, self).__init__()
        self.embedding_dim = arg_embedding_dim
        self.n_kernels = [10, 10, 10]
        self.kernel_sizes = [(1,1), (2,2), (3,3)]
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
                    len(NODE_KEY_LIST)+1-self.kernel_sizes[i],
                ), 
                padding=0
            )
            for i in range(len(self.kernel_sizes))
        ])
        self.linear = nn.Linear(sum(self.n_kernels), arg_embedding_dim)
        
    # input a batch of sequences (high-dimensional)
    # arg_seqs: (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
    # ??=1 since it's encoding a target
    def forward(self, arg_seqs):
        B = arg_seqs.shape[0]
        tmpn_nodes = arg_seqs.shape[1]
        tmp_dim0 = B * tmpn_nodes
        assert B==1
        assert tmpn_nodes==1
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
        self.linear = nn.Linear(sum(self.n_kernels), arg_embedding_dim)
        
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
        # tmp5 = F.relu(self.linear(tmp4)) # (dim0, embedding_dim)
        tmp5 = torch.sigmoid(self.linear(tmp4)) # (dim0, embedding_dim)
        tmp6 = tmp5.view(B, tmpn_nodes, self.embedding_dim) # (B=1, ??, embedding_dim)
        return tmp6


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
    # arg_target: (B=1, ??=1, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
    def compute_preference(self, arg_state, arg_target):
        B_state = arg_state.shape[0]
        B_target = arg_target.shape[0]
        assert B_state==1
        assert B_target==1
        
        # fixme: only support 1 target at a time
        n_targets = arg_target.shape[1]
        assert n_targets==1 
        
        tmp0_state = self.universal_token_encoder(arg_state) # (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
        tmp0_target = self.universal_token_encoder(arg_target) # (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
        tmp1_state = self.state_encoder(tmp0_state) # (B=1, embedding_dim)
        tmp1_target = self.target_encoder(tmp0_target) # (B=1, ??, embedding_dim)
        tmp2_state = tmp1_state
        
        # fixme: only support 1 target at a time
        tmp2_target = tmp1_target.view(B_target, self.embedding_dim) # (B=1, embedding_dim)
        
        tmp3 = torch.cat([tmp2_state, tmp2_target], 1) # (B=1, embedding_dim * 2)
        tmp4 = torch.sigmoid(self.hidden0(tmp3)) # (B=1, embedding_dim)
        return tmp4

    # arg_action: (B=1, ??=others, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
    def encode_action_list(self, arg_action):
        B = arg_action.shape[0]
        tmp0 = self.universal_token_encoder(arg_action) # (B=1, ??, len(NODE_KEY_LIST), embedding_dim)
        tmp1 = self.action_encoder(tmp0) # (B=1, ??, embedding_dim)
        return tmp1


# ## Pipeline Utils

# In[9]:


def get_reward0(arg_env, arg_wtg, arg_state):
    # (fixme) assume size is 3, you can also fix later
    # need to call these two methods first
    arg_env.get_available_actionable_elements(arg_env.get_current_state())
    # then you can safely use wtg functions
    tmp_computable_wtg = arg_wtg.wtg_graph
    tmp_current_nodes = arg_env.get_wtg_state(arg_wtg) # could be a list
    tmp_goal_edges = arg_wtg.get_goal_edges() # could be a list
    # then try to compute the lengths of shortest path
    tmp_lsps = []
    for a in tmp_current_nodes:
        for b in tmp_goal_edges:
            tmp_lsps.append( nx.shortest_path_length(tmp_computable_wtg, a, b[1]) ) # for edge, take the tgt node
    avg_lsp = sum(tmp_lsps)/len(tmp_lsps)
    # return 3.0 - avg_lsp
    return -avg_lsp


# In[10]:


# 1. roll out an action sequence
# 2. compute reward
# 3. policy gradient back propagation
def rollout(arg_env, arg_wtg, arg_agent, arg_optimizer, arg_maxn_steps, arg_target, arg_ep):
    # note: remember to clear the state
    arg_env.launch_app()
    
    rollout_outputs = []
    rollout_actions = []
    rollout_action_ids = []
    final_reward = 0.0
    
    print("stub 0")
    
    for i in range(arg_maxn_steps):
        time.sleep(1)
        state_i = arg_env.get_current_state()
        
        action_list = arg_env.get_available_actionable_elements(state_i)
        n_actions = len(action_list)
        if n_actions == 0:
            print("# no action is found, terminate.")
            # penalty
            final_reward = -3
            # no available actions any more
            break
          
        print("stub 1")
        # should wrap [] to make B=1
        # (B=1, ??=MAXN_STATE_NODES, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
        state_matrix_i = np.asarray([get_state_matrix(state_i)])
        # (B=1, ??=1, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
        target_matrix_i = np.asarray([[
            get_sentence_vector(arg_target)
        ]])
        # (B=1, ??=others, len(NODE_KEY_LIST), MAX_TOKEN_LENGTH)
        action_matrix_i = np.asarray([[
            get_element_vector(action_list[j])
            for j in range(len(action_list))
        ]])
        
#         print("state: {}".format(state_matrix_i.shape))
#         print("target: {}".format(target_matrix_i.shape))
#         print("action: {}".format(action_matrix_i.shape))
        
        t_state = Variable(torch.tensor(state_matrix_i, dtype=torch.long).to(device))
        t_target = Variable(torch.tensor(target_matrix_i, dtype=torch.long).to(device))
        t_action = Variable(torch.tensor(action_matrix_i, dtype=torch.long).to(device))
        
        B_state = t_state.shape[0]
        B_target = t_target.shape[0]
        B_action = t_action.shape[0]
        assert B_state==1
        assert B_target==1
        assert B_action==1
        print("stub 2")
        
        arg_agent.train()
        print("stub 2.1")
        tout_preference = arg_agent.compute_preference(t_state, t_target) # (B=1, embedding_dim)
        print("stub 2.2")
        tout_action = arg_agent.encode_action_list(t_action) # (B=1, ??, embedding_dim)
        print("stub 3")
        
#         print("tout_preference.shape={}".format(tout_preference.shape))
#         print("tout_action.shape={}".format(tout_action.shape))
        
        # ====> using cosine similarity
        # (n_actions, spec_dims)
        # t0_output = t_output.expand_as(t_pool)
        # t_cos = F.cosine_similarity(t0_output, t_pool, dim=1)
        # t_act = F.log_softmax(t_cos, dim=0)
        # ====> directly mm similarity
        # note: assuming B=1 already
        tout0_preference = tout_preference.view(-1,1) # (embedding_dim, 1)
        tout0_action = tout_action.view(-1, EMBEDDING_DIM) # (n_actions, embedding_dim)
        tout0_mm = torch.mm(tout0_action, tout0_preference)  # (n_actions, 1)
        tout1_mm = tout0_mm.view(-1) # (n_actions,)
        tout2_mm = F.log_softmax(tout1_mm)
#         print("# tout2_mm: {}".format(tout2_mm))
        print("stub 4")
        
        if random.random()<max(0.1, 1.0-ep/20):
            # explore
            selected_action_id = random.choice(list(range(len(action_list))))
            print("# [explore] selected_action_id (rnd): {}, log-sim: {}".format(selected_action_id, tout2_mm[selected_action_id]))
        else:
            # exploit
            probs = tout2_mm.exp().tolist()
            selected_action_id = np.argmax(probs)
            # selected_action_id = torch.argmax(tout2_mm, dim=0).tolist()
            print("# [exploit] selected_action_id (mul): {}, log-sim: {}".format(selected_action_id, tout2_mm[selected_action_id]))
#         else:
#             # exploit
#             probs = tout2_mm.exp().tolist()
#             selected_action_id = random.choices(list(range(len(action_list))), weights=probs, k=1)[0]
#             # selected_action_id = torch.argmax(tout2_mm, dim=0).tolist()
#             print("# [exploit] selected_action_id (mul): {}, log-sim: {}".format(selected_action_id, tout2_mm[selected_action_id]))
        
        # perform action
        arg_env.perform_action(action_list[selected_action_id])
        next_state = arg_env.get_current_state()
        dreward = get_reward0(arg_env, arg_wtg, next_state)
        # dreward = 0.0
        print("  # r: {}".format(dreward))
        final_reward += dreward
        
        # store the choices
        rollout_outputs.append(tout2_mm)
        rollout_actions.append(action_list)
        rollout_action_ids.append(selected_action_id)
        
        # input("PAUSE")
        
#     # here we use the final reward as the cumulative reward
#     final_state = arg_env.get_current_state()
#     # test whether goal states are reached
#     rlist = arg_env.get_reached_goal_states("train")
#     print("# final reward000: {}".format(final_reward))
#     if len(rlist)>0:
#         print("# goal state: {}".format(rlist))

#     print("# final reward: {}".format(final_reward))
    
#     rollout_loss = []
#     current_reward = final_reward
#     # reverse from the last to first
#     for i in range(len(rollout_outputs))[::-1]:
#         rollout_loss.append( current_reward * (-rollout_outputs[i][rollout_action_ids[i]]) )
#         current_reward *= 0.8 # decay
#     rollout_loss = rollout_loss[::-1]
    
#     optimizer.zero_grad()
#     loss = sum(rollout_loss)
#     loss.backward()
#     optimizer.step()
        
        


# In[ ]:





# ## Top-Level Control Flow

# In[11]:


from main import *

CURR_DIR = os.path.dirname(os.getcwd())
OUTPUT_DIR = os.path.join(CURR_DIR, "results")

args = {
    "path": "../results/test_app_1/testapp_1.apk",
#     "path": "../results/test_app_2/testapp_2.apk",
#     "path": "../test/com.github.cetoolbox_11/app_simple0.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/Wordpress_394/Wordpress_394.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/com.zoffcc.applications.aagtl_31/com.zoffcc.applications.aagtl_31.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/Translate/Translate.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/com.chmod0.manpages_3/com.chmod0.manpages_3.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/tmp/Book-Catalogue/Book-Catalogue.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/out.andFHEM.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/out.blue-chat.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/out.CallMeter3G-debug.apk",
#     "path": "/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/out.Lucid-Browser.apk",
    "output": "../results/",
    "wtginput": "../results/test_app_2/",
    "goalstates": "../results/test_app_2/goals_caller.json",
}

if args["path"] is not None:
    pyaxmlparser_apk = APK(args["path"])
    apk_base_name = os.path.splitext(os.path.basename(args["path"]))[0]
else:
    parser.print_usage()
    sys.exit(1)
    
goal_states = {}
if args["goalstates"] is not None:
    with open(args["goalstates"], 'r') as fp:
        goal_states = json.load(fp)

else:
    parser.print_usage()
    sys.exit(1)

if args["output"] is not None:
    OUTPUT_DIR = args["output"]

output_dir = os.path.join(OUTPUT_DIR, 'exploration_output', apk_base_name)

wtg = None
if args["wtginput"]:
    wtg = args["wtginput"] #os.path.join(args.wtginput, apk_base_name)

if os.path.exists(output_dir):
    rmtree(output_dir)

os.makedirs(output_dir, exist_ok=True)

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
run_adb_as_root(log, device_serial)
apk_obj = Apk(args["path"], uiautomator_device, output_dir, log, device_serial)
wtg_obj = WTG(wtg, log)
wtg_obj.set_goal_nodes(goal_states)
apk_obj.launch_app()
# to track some goal state at startup, you don't have to do this
apk_obj.clean_logcat()


# In[ ]:


nsteps = 3
neural_agent = NeuralAgent(EMBEDDING_DIM).to(device)
optimizer = torch.optim.SGD(neural_agent.parameters(), lr=0.1)
target = ["com","example","priyanka","testapp","BasicViewsActivity","void","goToMain","android","view","View"]
target += [[""]] * ( len(NODE_KEY_LIST)-len(target) )
st = time.time()
for ep in range(100000):
    print("# ep{}, time elapsed: {}".format(ep, time.time()-st))
    rollout(apk_obj, wtg_obj, neural_agent, optimizer, nsteps, target, ep)
#     random_rollout(apk_obj, nsteps, target)


# In[ ]:





# In[ ]:


apk_obj.get_reached_goal_states("train")


# In[ ]:


apk_obj.get_current_state()


# In[ ]:


apk_obj.get_available_actionable_elements(apk_obj.get_current_state())


# In[ ]:


apk_obj.get_wtg_state(wtg_obj)


# In[ ]:


wtg_obj.get_goal_edges()


# In[ ]:


wtg_obj.wtg


# In[ ]:


nx.all_pairs_shortest_path(wtg_obj.wtg)


# In[ ]:


nx.shortest_path(wtg_obj.wtg, apk_obj.get_wtg_state(wtg_obj)[0], apk_obj.get_wtg_state(wtg_obj)[0])


# In[ ]:


temp = wtg_obj.get_goal_edges()


# In[ ]:


temp[0]


# In[ ]:


temp[0][0].node_key


# In[ ]:


apk_obj.get_wtg_state(wtg_obj)


# In[ ]:


wtg_obj.wtg_graph


# In[ ]:


wtg_obj.nodes


# In[ ]:


wtg_obj.wtg


# In[ ]:


wtg_obj.wtg.nodes


# In[ ]:


wtg_obj.wtg_graph


# In[ ]:


nx.shortest_path(wtg_obj.wtg_graph, apk_obj.get_wtg_state(wtg_obj)[0], apk_obj.get_wtg_state(wtg_obj)[0])


# In[ ]:


nx.shortest_path_length(wtg_obj.wtg_graph, apk_obj.get_wtg_state(wtg_obj)[0], apk_obj.get_wtg_state(wtg_obj)[0])


# In[ ]:


wtg_obj.get_goal_edges()


# In[ ]:


nx.shortest_path_length(
    wtg_obj.wtg_graph, 
    apk_obj.get_wtg_state(wtg_obj)[0],
    wtg_obj.get_goal_edges()[0][1]
)


# In[ ]:




