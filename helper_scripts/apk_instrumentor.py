import subprocess
import sys
sys.path.append("..")
import angr
from enum import Enum
import datetime
import argparse
import json
from pprint import pprint
from collections import defaultdict, OrderedDict
from difflib import get_close_matches
import sys
import _pickle as pickle
import os
import subprocess
import logging
import frida
import time
import signal
import types
import time
import glob
import threading
from pyaxmlparser import APK
from lib.helper import *
import IPython
import random
import shutil
from distutils.dir_util import copy_tree

def sign_apk(apk_path, log):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automatically instrument apks and sign them')
    parser.add_argument('--app-dir', '-ad', dest='appdir', help='The path to the directory containing apks')
    parser.add_argument("--output-dir", "-od", dest="outputdir", help="The path to output directory where instrumented apks will be stored")

    args = parser.parse_args()

    if args.appdir is not None:
        apk_path_pattern = os.path.join(args.appdir, "**/*.apk")
        apks = glob.glob(apk_path_pattern)

    else:
        parser.print_usage()
        print("App dir path can not be None!")
        sys.exit(1)

    # Setting the path for log file
    log_path = os.path.join(args.outputdir, 'analysis.log')
    log = init_logging('analyzer.instrumentation', log_path, file_mode='w', console=True)

    current_dir = os.path.dirname(os.path.realpath(__file__))
    APK_INSTRUMENTER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../ApkInstrumentor")
    APK_SIGNER_PATH = os.path.join(APK_INSTRUMENTER_PATH, "demo/Android")
    temp_output_dir = os.path.join(APK_INSTRUMENTER_PATH, "demo/Android/Instrumented")

    for apk in apks:
        coverage_file_name = os.path.splitext(os.path.basename(apk))[0] + ".em"
        coverage_em_file_path = os.path.join(os.path.dirname(apk), coverage_file_name)
        apk_output_dir = os.path.join(args.outputdir, os.path.splitext(os.path.basename(apk))[0])

        if os.path.exists(apk_output_dir):
            shutil.rmtree(apk_output_dir)

        os.makedirs(apk_output_dir, exist_ok=True)
        os.chdir(APK_INSTRUMENTER_PATH)
        cmd = './gradlew run --args="AndroidLogger auto_instrument %s"' % apk
        status_code = os.system(cmd)

        if status_code == 0:
            log.info("Successfully instrumented %s " % os.path.basename(apk))
            os.chdir(APK_SIGNER_PATH)
            apk_output_path = os.path.join(temp_output_dir, os.path.basename(apk))
            signing_cmd = './sign.sh %s key "android"' % apk_output_path
            status_code = os.system(signing_cmd)

            if status_code == 0:
                log.info("%s signed successfully" % os.path.basename(apk))
                apk_base_name = os.path.basename(apk)

                coverage_out_file = apk_base_name.replace(".apk", ".em")
                copy_tree(temp_output_dir, apk_output_dir)
                shutil.copyfile(coverage_em_file_path, os.path.join(apk_output_dir, coverage_out_file))
        else:
            log.warning("Build failed for some reason for %s" % os.path.basename(apk))

        os.chdir(current_dir)