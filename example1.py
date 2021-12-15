import time
import sys
from martha.apk import Apk
from martha.apk_environment import ApkEnvironment
from martha.logcat_watcher import LogcatWatcher
from martha.simple_mlp import SimpleMLP
import os

import logging
logging.disable(logging.INFO)
logging.disable(logging.WARNING)
# logging.disable(logging.NOTSET)

import ray
from ray import tune
from ray.rllib.agents import ppo, dqn
from ray.rllib.models import ModelCatalog
from ray.tune.logger import pretty_print

logcat_watcher = LogcatWatcher()
env_config = {
    "apk_folder": "{}/benchmarks".format(os.getcwd()),
    # "apk_name": "de.vanitasvitae.enigmandroid_18.apk",
    "apk_name": "app-debug.apk",
    "max_step": 4,
    "logcat_watcher": logcat_watcher,
}
# need to construct the vocab first to provide parameters for nn
tmp_environment = ApkEnvironment(config=env_config)

ray.init(local_mode=True)
ModelCatalog.register_custom_model("simple_mlp", SimpleMLP)

ppo_config = ppo.DEFAULT_CONFIG.copy()
rl_config = {
    # number of fragments (actions) in one episode
    # since here we only have 1 worker, it's the same as batch size
    # generally batch_size >= fragment_length, for multiple workers
    "rollout_fragment_length": 128,
    "train_batch_size": 128,

    # mini batch size <= train batch size
    "sgd_minibatch_size": 16,

    "env": ApkEnvironment,
    "env_config": env_config,
    "model": {
        "custom_model": "simple_mlp",
        "custom_model_config": {
            "num_rx_embeddings": ApkEnvironment.RWIDTH+1, # +1 is for extra padding position
            "num_ry_embeddings": ApkEnvironment.RHEIGHT+1,
            "embedding_size": 16,
            "hidden_size": 32,
            "state_size": ApkEnvironment.RWIDTH*ApkEnvironment.RHEIGHT,
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