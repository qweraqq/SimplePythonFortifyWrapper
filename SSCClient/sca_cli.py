#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import getopt
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def func_simple_sca_cli(argv):
    """
    fortify sca命令行的简单封装，用于扫描指定目录下的指定repos目录
    为什么这么设计？这个命令行主要是用户扫描大量的repos，这些repos放在同一个目录下，比如：repos/app1 repos/app2 repos/app3

    fortify sca执行正常可以分为四个阶段：1，clean 2. translate 3. scan 4. generate reports(optional)
    实现的这个函数就是将阶段1、2、3进行了sca常用默认参数的封装，方便调用
    如果要调用更为复杂的sca参数，可以使用fortify自带的scan wizard来生成
    :param argv: 命令行调用的参数
    :return:
    """
    root_directory = ""
    repo = ""
    try:
        opts, args = getopt.getopt(argv, "hr:d:v")
    except getopt.GetoptError:
        print("Usage: fortify_scan -d <root_directory> -r <repo> <-v>")
        sys.exit(2)

    if len(opts) < 1:
        print("Usage: fortify_scan -d <root_directory> -r <repo> <-v>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-v':
            logger.setLevel(logging.DEBUG)
            logging.debug("DEBUG: Staring fortify_scan ...")

    for opt, arg in opts:
        if opt == '-d':
            root_directory = Path(arg)
            logging.debug("DEBUG: func_simple_sca_cli root directory is {}".format(root_directory))
        if opt == '-r':
            repo = arg
            logging.debug("DEBUG: Repos is {}".format(repo))
        if opt == '-h':
            print("Usage: fortify_scan -d <ROOT_DICTIONARY> -r <repo> <-v>\r\n "
                  "Example:\r\nfortify_scan -d D:\\repos -r app1 -v")
            sys.exit()

    if not os.path.exists(root_directory):
        logging.error("ERROR:WRONG PATH {}".format(root_directory))
        sys.exit(2)

    os.chdir(root_directory)
    repo_path = os.path.join(root_directory, repo)
    if not os.path.exists(repo_path):
        logging.error("ERROR: WRONG repos PATH {}".format(repo_path))
        sys.exit(2)
    logging.debug("DEBUG: repos_dictionary is {}".format(repo_path))

    with open(os.path.join(root_directory, "fortify_error_log.txt"), "a+") as f:
        logging.debug("DEBUG: func_simple_sca_cli is cleaning legacy builds")
        subprocess.call(["sourceanalyzer", "-b", repo, '-clean', '-quiet'],
                        cwd=repo_path, stderr=f, shell=True, close_fds=True)
        logger.debug("DEBUG: func_simple_sca_cli is translating")
        subprocess.call(["sourceanalyzer", "-b", repo, "-64", "-source", "1.8", ".", '-quiet',
                         "-exclude", "**/test/*", "-encoding", "UTF-8"],
                        cwd=repo_path, stderr=f, shell=True, close_fds=True)
        logger.debug("DEBUG: func_simple_sca_cli is scanning ")
        subprocess.call(["sourceanalyzer", "-b", repo, "-64", "-format", "fpr", '-quiet', "-encoding", "UTF-8",
                         "-f", os.path.join(root_directory, repo + '.fpr'), "-scan"],
                        cwd=repo_path, stderr=f, shell=True, close_fds=True)


def func_simple_sca_batch_scanner(root_directory):
    """
    使用SCA逐一扫描目录下所有的文件夹，比如：repos/app1 repos/app2 repos/app3
    :param root_directory: 指定目录
    :return:
    """
    root_directory = Path(root_directory)
    repos = [_ for _ in os.listdir(root_directory) if os.path.isdir(os.path.join(root_directory, _))]
    for _ in repos:
        logging.info("repo {} is being analysed by Fortify SCA".format(_))
        arg = ["-d", root_directory, "-r", str(_)]
        start_time = time.perf_counter()
        func_simple_sca_cli(arg)
        end_time = time.perf_counter()
        run_time = end_time - start_time
        logging.info("repo {} scanning finished in {}".format(_, time.strftime("%H:%M:%S", time.gmtime(run_time))))
