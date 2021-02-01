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


def analyze_apk(apk):
    info("Analysis started: %s" % os.path.basename(apk))
    apk_base_name = os.path.splitext(os.path.basename(apk))[0]
    result_dir = os.path.join(RESULT_DIR, apk_base_name)

    if os.path.exists(result_dir):
        rmtree(result_dir)

    if not os.path.exists(result_dir):
        os.makedirs(result_dir, exist_ok=True)

    log_path = os.path.join(result_dir, 'analysis.log')
    log = init_logging('analyzer.%s' % apk_base_name, log_path, file_mode='w', console=True)

    # Record analysis start time
    now = datetime.datetime.now()
    analysis_start_time = now.strftime(DATE_FORMAT)
    info('Analysis started at: %s' % analysis_start_time)
    start_time = time.time()

    #if os.path.exists(apk_obj_filepath):
    try:
        apk_obj = Apk(apk, result_dir, log)

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
    parser.add_argument("--apk", "-a", dest="apk", help="The path to the apk or the directory containing apk")
    parser.add_argument("--output", "-o", dest="output", help="The path to the output directory")

    args = parser.parse_args()


    if args.apk is not None:
        APK_PATH = args.apk

    apkfiles = []

    if os.path.isdir(APK_PATH):
        for path, subdirs, files in os.walk(APK_PATH):
            for x in files:
                apkfiles.append(os.path.join(APK_PATH, x))
    else:
        custom_apkpath = APK_PATH
        apkfiles.append(custom_apkpath)


    if args.output is not None:
        RESULT_DIR = args.output


    apks_to_be_analyzed = []
    for apk in apkfiles:
        apks_to_be_analyzed.append(apk)


    # Analyze the apks using mutiprocessing pool if number of apks
    # is more than one
    if len(apkfiles) > 1:
        cpu_count = int(CPU_CORES)
        with multiprocessing.Pool(cpu_count) as pool:
            pool.map(analyze_apk, apks_to_be_analyzed)

        pool.join()

    else:
        analyze_apk(apkfiles[0])

    
    ## apk callback extraction
