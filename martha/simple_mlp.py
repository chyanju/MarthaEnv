import numpy as np

from ray.rllib.models.torch.torch_modelv2 import TorchModelV2
from ray.rllib.utils.framework import try_import_torch
from ray.rllib.models.preprocessors import get_preprocessor
from ray.rllib.utils.annotations import override

torch, nn = try_import_torch()

class SimpleMLP(TorchModelV2, nn.Module):
    def __init__(self, obs_space, action_space, num_outputs, model_config, name):
        nn.Module.__init__(self)
        super().__init__(obs_space, action_space, num_outputs, model_config, name)
        self.config = model_config["custom_model_config"]

        self.rx_embedding = nn.Embedding(
            num_embeddings=self.config["num_rx_embeddings"],
            embedding_dim=self.config["embedding_size"],
            padding_idx=0,
        )
        self.ry_embedding = nn.Embedding(
            num_embeddings=self.config["num_ry_embeddings"],
            embedding_dim=self.config["embedding_size"],
            padding_idx=0,
        )

        self.action_encoder = nn.Linear(
            in_features=2*self.config["embedding_size"],
            out_features=self.config["hidden_size"],
        )
        self.state_encoder = nn.Linear(
            in_features=self.config["state_size"],
            out_features=self.config["hidden_size"],
        )

        self.bias = nn.Linear(
            in_features=self.config["hidden_size"],
            out_features=1,
        )

        self.value_branch = nn.Linear(
            in_features=self.config["hidden_size"],
            out_features=1,
        )

        # holds the current "base" output (before logits layer).
        self._state_hidden = None

    @override(TorchModelV2)
    def value_function(self):
        assert self._state_hidden is not None, "self._state_hidden is None, call forward() first."
        return torch.reshape(self.value_branch(self._state_hidden), [-1])

    @override(TorchModelV2)
    def forward(self, input_dict, state, seq_lens):
        # note: somewhat obs_flat is storing action_mask, so you need to use obs[inv] here
        B = input_dict["obs"]["n_actions"].shape[0]

        # tmp_state: (B, RHEIGHT, RWIDTH) -> (B, RHEIGHT*RWIDTH)
        tmp_state = input_dict["obs"]["state"].view(B, self.config["state_size"])
        # print("state shape: {}".format(tmp_state.shape))
        tmp_state_hidden = self.state_encoder(tmp_state) # (B, hidden_size)
        self._state_hidden = tmp_state_hidden # set the state vector

        # tmp_n_actions: (B,)
        # tmp_action_x: (B, SCREEN_MAX_ACTIONS)
        # tmp_action_y: (B, SCREEN_MAX_ACTIONS)
        tmp_n_actions = input_dict["obs"]["n_actions"].flatten().tolist()
        tmp_action_x = input_dict["obs"]["action_x"].int() +1 # then 0 becomes padding
        tmp_action_y = input_dict["obs"]["action_y"].int() +1 # then 0 becomes padding

        tmp_xembd = self.rx_embedding(tmp_action_x) # (B, SCREEN_MAX_ACTIONS, embd)
        tmp_yembd = self.ry_embedding(tmp_action_y) # (B, SCREEN_MAX_ACTIONS, embd)
        tmp_embd = torch.cat([tmp_xembd, tmp_yembd], axis=2) # (B, SCREEN_MAX_ACTIONS, 2*embd)
        tmp_action = self.action_encoder(tmp_embd) # (B, SCREEN_MAX_ACTIONS, hidden_size)

        # then compute preference
        tmp_sh = tmp_state_hidden.view(B, self.config["hidden_size"], 1) # (B, hidden_size, 1)
        # simulate matrix multiplication
        tmp0 = torch.matmul(tmp_action, tmp_sh) # (B, SCREEN_MAX_ACTIONS, 1)
        tmp1 = tmp0.view(B, self.config["output_size"]) # (B, SCREEN_MAX_ACTIONS)
        tmp_bias = self.bias(tmp_action).view(B, self.config["output_size"]) # (B, SCREEN_MAX_ACTIONS, 1) -> (B, SCREEN_MAX_ACTIONS)
        tmp_out = tmp1 + tmp_bias # (B, SCREEN_MAX_ACTIONS)

        # apply masking, ref: https://towardsdatascience.com/action-masking-with-rllib-5e4bec5e7505
        inf_mask = torch.maximum( 
            torch.log(input_dict["obs"]["action_mask"]), 
            torch.tensor(torch.finfo(torch.float32).min) 
        )

        return tmp_out + inf_mask, []

