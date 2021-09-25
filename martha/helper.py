import os
import sys
import json
import glob
import copy
import shutil
import hashlib
import logging
import requests
from enum import IntEnum

# Globals
RPC_ENDPOINT = 'http://192.168.51.61:8545'
API_KEY = '2263VM492QTUNN3NRH5KN2II9VN9BM8UT2'
DATE_FORMAT = '%Y-%m-%d %I:%M:%S %p'
DATASET_DIR = '../../crawled-contracts'
DB_PATH = os.path.join(DATASET_DIR, 'contracts.sqlite')
LOG_PATH = os.path.join(DATASET_DIR, 'contracts-crawler.log')

# ANSI color codes
class Color:
    COLOR_SEQ = "\033[1;%dm"
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    LIGHT_GRAY = '\033[37m'
    DEFAULT = '\033[39m'
    DARK_GRAY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'

LOGGER_COLORS = {
    'DEBUG': Color.DARK_GRAY,
    'INFO': Color.DARK_GRAY,
    'WARNING': Color.GREEN,
    'ERROR': Color.RED,
    'CRITICAL': Color.CYAN
}


# Define error codes
class Error(IntEnum):
    ENV_VAR_NOT_SET = 1
    FILE_NOT_FOUND = 2


def check_env_var(env_var):
    # Check if environment variable is set
    try:
        env_val = os.environ[env_var]
        return env_val
    except KeyError as ke:
        print("[*] Set and export " + env_var + " environment variable")
        sys.exit(Error.ENV_VAR_NOT_SET)


def check_if_file_exists(file):
    if os.path.isfile(file):
        return True
    else:
        err('File does not exist: %s' % file)
        return False


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        record = copy.copy(record)
        levelname = record.levelname
        if levelname in LOGGER_COLORS:
            levelname_color = Color.COLOR_SEQ % (30 + LOGGER_COLORS[levelname]) + levelname + Color.ENDC
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


# Initialize a logger that does not interfere with
# Celery family of loggers, especially the root logger
def init_logging(logger_name, log_file=None, file_mode='a', console=False):
    # Configure log format
    log_format_string = "[%(levelname)s] | %(asctime)s | %(name)-15s | %(message)s"
    date_fmt_string = DATE_FORMAT
    formatter = logging.Formatter(log_format_string, date_fmt_string)
    log = logging.getLogger(logger_name)
    log.setLevel(logging.INFO)
    # Turn off log message propagation all the way to the root logger.
    # If root logger is configured to have one or more handlers by
    # other modules, all log messages sent to our logger appears
    # those many times. Disabling root logger is not an elegant option,
    # because that turns off log messages (which might be important)
    # sent by other modules.
    log.propagate = False

    # Do *NOT* configure root logger will Celery.
    # Logs will be sent to console or wherever Celery
    # sends the logs by default
    # logging.basicConfig(filename=log_file, filemode=file_mode, format=log_format_string, datefmt=date_fmt_string, level=logging.INFO)

    # Configure and attach a file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, mode=file_mode)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)

    # Configure and attach a console handler
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        # color_formatter = ColoredFormatter()
        console_handler.setFormatter(formatter)
        # console_handler.setFormatter(color_formatter)
        log.addHandler(console_handler)
    
    # import logging_tree; logging_tree.printout()
    return log


# We forgot to close the logger explicitly.
# Hundreds of file handles were left open from
# each of the analysis task. If <pid> is the PID
# of the pool worker, the open file handles can be
# listed using: "cat /proc/<pid>/fd". This is why
# the multiprocessing pool used to hang after some time
# Ref: https://stackoverflow.com/a/15474586
def del_logging(log):
    handlers = log.handlers[:]
    for handler in handlers:
        handler.flush()
        handler.close()
        log.removeHandler(handler)
    del(log)


def get_text_hash(text):
    text = text.replace('\r\n', '\n')
    text_hash = hashlib.md5(text.encode()).hexdigest()
    return text_hash


def save_to_disk(directory, contract_name, source_code, file_hash_map, save_file=True): 
    file_name = contract_name + '.sol'
    file_path = os.path.join(directory, file_name)
    file_index = 0
    does_file_exist = False
    is_existing = False
    new_source_hash = get_text_hash(source_code)

    # Is file_hash_map populated? If not, then store the
    # hashes of the files in the destination directory
    if len(file_hash_map) == 0:
        sol_file_regex = os.path.join(directory, '*.sol')
        for existing_contract_path in glob.glob(sol_file_regex):
            with open(existing_contract_path, 'r') as fp:
                existing_contract_source_code = fp.read()
            existing_contract_hash = get_text_hash(existing_contract_source_code)
            existing_contract_name = os.path.basename(existing_contract_path)
            file_hash_map[existing_contract_hash] = existing_contract_name

    # Look up the hash map to check if the same file exists already
    existing_file_name = file_hash_map.get(new_source_hash)
    if existing_file_name is not None:
        return existing_file_name, True      # is_existing = True

    # If the same file doesn't exist, even with some other name,
    # we store the file with its original name. In case of a name
    # collision, we append a numeric suffix: contract.sol => contract_xx.sol
    while True:
        does_file_exist = os.path.isfile(file_path)
        if does_file_exist:
            with open(file_path, 'r') as fp:
                existing_source = fp.read()

                existing_source_hash = hashlib.md5(existing_source.encode()).hexdigest()
                if new_source_hash == existing_source_hash:
                    is_existing = True
                    break

            # Form the file name with the next numeric prefix
            file_index += 1
            file_name = '%s_%d.sol' % (contract_name, file_index)
            file_path = os.path.join(directory, file_name)
        else:
            break
    
    # Update the file hash map
    file_hash_map[new_source_hash] = file_name

    if save_file:
        if not is_existing:
            with open(file_path, 'w') as fp:
                fp.write(source_code)
    
    return file_name, is_existing


def err(string):
    print(Color.RED + '[x] ' + str(string) + Color.ENDC)


def warn(string):
    print(Color.YELLOW + '[-] ' + str(string) + Color.ENDC)


def success(string):
    print(Color.GREEN + '[@] ' + str(string) + Color.ENDC)


def info(string):
    print(Color.CYAN + '[#] ' + str(string) + Color.ENDC)


def debug(string):
    print(Color.DARK_GRAY + '[*] ' + str(string) + Color.ENDC)


# https://www.peterbe.com/plog/best-practice-with-retries-with-requests
def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), session=None):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Read JSON configuration file
def read_config(config_file):
    config_file = config_file.strip()
    
    # File not provided
    if config_file is None or config_file is '':
        err('Configuration file not provided')
        sys.exit(1)

    # Read configuration file
    try:
        with open(config_file, 'r') as fp:
            config = json.load(fp)
    
    # File not found
    except FileNotFoundError as fnfe:
        err('Configuration file not found: %s' % config_file)
        sys.exit(1)
    
    # JSON malformed
    except json.decoder.JSONDecodeError as jde:
        err('Configuration JSON malformed: %s' % config_file)
        sys.exit(1)

    return config


# Delete a file or directory in a robust way
def delete_path(path):
    try:
        # path could either be relative or absolute
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)                             # Remove the file
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)     # Remove the dir and all of its contents
        else:
            pass
    
    except:
        pass
