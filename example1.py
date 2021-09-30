import time
import sys
from martha.apk import Apk
from martha.apk_environment import ApkEnvironment
from martha.simple_gru import SimpleGRU
import os

import ray
from ray import tune
from ray.rllib.agents import ppo, dqn
from ray.rllib.models import ModelCatalog
from ray.tune.logger import pretty_print

env_config = {
    "apk_folder": "{}/benchmarks".format(os.getcwd()),
    "apk_name": "com.Healthtipsbd.allergictreatment",
    "max_step": 4,
}
# need to construct the vocab first to provide parameters for nn
tmp_environment = ApkEnvironment(config=env_config, dummy=True)

ray.init(local_mode=True)
ModelCatalog.register_custom_model("simple_gru", SimpleGRU)

ppo_config = ppo.DEFAULT_CONFIG.copy()
rl_config = {
    "env": ApkEnvironment,
    "env_config": env_config,
    "model": {
        "custom_model": "simple_gru",
        "custom_model_config": {
            "num_embeddings": len(tmp_environment.token_list),
            "embedding_size": 16,
            "encoder_input_size": 24,
            "encoder_hidden_size": 32,
            "output_size": ApkEnvironment.SCREEN_MAX_ACTIONS,
        },
    },
    "num_workers": 1,
    "framework": "torch",
}
ppo_config.update(rl_config)
agent = ppo.PPOTrainer(env=ApkEnvironment, config=ppo_config)

for i in range(100):
    print("# i={}".format(i))
    res = agent.train()

ray.shutdown()