'''
=======================
	Generic Imports
=======================
'''
import sys
sys.path.append("..")
import angr
import datetime
from enum import Enum
import json
from pprint import pprint
from collections import defaultdict
from difflib import get_close_matches
import sys
import pickle
#import _pickle as pickle
import os, sys
import subprocess
from collections import defaultdict
from shutil import rmtree
from pyaxmlparser import APK
import time
from lib.helper import *
import argparse
import multiprocessing
import traceback
import glob

'''
=======================
	Global Variables
=======================
'''
PROJECT_ROOT = check_env_var('GOAL_EXPLORER')
sys.path.insert(1, os.path.join(PROJECT_ROOT, 'utils'))

'''
=======================
	Module Imports
=======================
'''

from utils import get_method_key
from callgraph import CallGraph
from apk import Apk

'''
=======================
	Start of main
=======================
'''
CPU_CORES = 2


def analyze_apk(apk, gatordir, client_name):
    info("Analysis started: %s" % os.path.basename(apk))
    apk_base_name = os.path.splitext(os.path.basename(apk))[0]
    result_dir = os.path.join(RESULT_DIR, 'static_output', apk_base_name)

    if os.path.exists(result_dir):
        rmtree(result_dir)

    if not os.path.exists(result_dir):
        os.makedirs(result_dir, exist_ok=True)

    log_path = os.path.join(result_dir, 'analysis.log')
    analysis_console_output_path = os.path.join(result_dir, "console_output.log")
    log = init_logging('analyzer.%s' % apk_base_name, log_path, file_mode='w', console=True)

    # Record analysis start time
    now = datetime.datetime.now()
    analysis_start_time = now.strftime(DATE_FORMAT)
    info('Analysis started at: %s' % analysis_start_time)
    start_time = time.time()

    #if os.path.exists(apk_obj_filepath):
    try:
        gator_executable = os.path.join(gatordir, "gator")
        cmd = ['python3', gator_executable, 'a', '-p %s' % apk, '-o %s' % result_dir, '-client %s' % client_name]
        cmd.extend(['>>', analysis_console_output_path, '2>&1'])
        cmd_string = ' '.join(filter(lambda x: x != '', cmd))
        status_code = os.system(cmd_string)
        info("Status code: %d" % status_code)
        log.info("Status code: %d" % status_code)

    except:
        traceback.print_exc()
        log.warning("Analysis for %s errored out" % apk_base_name)

    # Record analysis duration

    end_time = time.time()
    analysis_duration = end_time - start_time
    info('Analysis took %f seconds' % analysis_duration)

    # Record analysis end time
    now = datetime.datetime.now()
    analysis_end_time = now.strftime(DATE_FORMAT)
    info('Analysis finished at: %s' % analysis_end_time)

    info("Analysis completed: %s " % (apk_base_name))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyzes apk files")
    parser.add_argument("--app-dir", "-a", dest="appdir", help="The path to the apk or the directory containing apk")
    parser.add_argument("--gator-dir", "-g", dest="gatordir", help="The path to the input directory to gator")
    parser.add_argument("--client-name", "-c", dest="client", help="The name of the client to run with gator")
    parser.add_argument("--output", "-o", dest="output", help="The path to the output directory")

    args = parser.parse_args()


    if args.appdir is not None:
        APK_PATH = args.appdir

    apkfiles = []
    glob_pattern = args.appdir + "/*.apk"
    apk = glob.glob(glob_pattern)[0]

    if args.output is not None:
        RESULT_DIR = args.output

    analyze_apk(apk, args.gatordir, args.client)


