#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import shutil
import subprocess
import sys
from commands import getstatusoutput
from os import chdir, environ
from os.path import join, exists, split, abspath, isdir, isfile
from tempfile import mkdtemp
from threading import Timer
from time import time

"""
Module for System Testing

To add a new test add it in the test array in main.
"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"

DEFAULT_DUMP_PATH = "/tmp/"
DUMP = ""
EXEC_PATH = ""
CONFIG_CREATOR_PATH = ""

NODE_RDY = "Both socket binded, node ready to talk with the Master."

NODE_TIMEOUT = 5
MASTER_TIMEOUT = 20


def erase_dump():
    if exists(DUMP):
        shutil.rmtree(DUMP)
    return 0


def exec_node(config):
    if not isdir(EXEC_PATH):
        return None, 1, "ERROR: Path doesn't exists >> " + EXEC_PATH

    if not isdir(join(EXEC_PATH, "src")):
        return None, 1, "ERROR: Path doesn't exists >> " + EXEC_PATH + "/src"

    node = None
    try:
        node = subprocess.Popen(
            [EXEC_PATH + "/src/node",
             "-c",
             config + ".conf"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
    except OSError as e:
        return node, 1, "ERROR: Exec could not be accesed >> " + EXEC_PATH + "/src/node"

    timer = Timer(NODE_TIMEOUT, node.terminate)
    timer.start()

    stdout_lines = iter(node.stderr.readline, "")
    for stdout_line in stdout_lines:
        if NODE_RDY in stdout_line:
            break

    if timer.is_alive():
        timer.cancel()
        return node, 0, ""
    else:
        return node, 1, "FAILURE: Timeout"


def exec_master(master_args, master_name, cryptoki_conf="cryptoki.conf"):
    if isfile(cryptoki_conf):
        environ["TCHSM_CONFIG"] = abspath(cryptoki_conf)
    else:
        return None, 1, "ERROR: TCHSM_CONFIG env. var. could not be set."

    master = None
    try:
        master = subprocess.Popen(
            master_args,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
    except OSError:
        return None, 1, "ERROR: Exec could not be accesed >> " + master_name

    timer = Timer(MASTER_TIMEOUT, master.terminate)
    if master is not None:
        timer.start()

    master.wait()

    if timer.is_alive():
        timer.cancel()
        if master.returncode != 0:
            return master, master.returncode, "FAILURE: Master return code: " + str(master.returncode)
        return None, master.returncode, ""
    else:
        return master, 1, "FAILURE: Timeout"


def close_node(node_proc):
    if node_proc is not None:
        node_proc.stderr.close()
        node_proc.terminate()


def close_master(master):
    if master is not None:
        master.stdout.close()
        master.stderr.close()


def close_nodes(nodes):
    for node in nodes:
        close_node(node)


def create_dummy_file():
    fd = open("to_sign.txt", "w")
    fd.write(":)\n")
    return fd


# NODE ONLY TESTS
def test_one_node():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    proc, ret, mess = exec_node("node1")
    close_node(proc)
    return ret, mess


def test_two_nodes():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node1, ret1, mess1 = exec_node("node1")
    if ret1 == 1:
        close_node(node1)
        return 1, mess1

    node2, ret2, mess2 = exec_node("node2")

    close_nodes([node1, node2])
    return ret2, mess2


def test_opening_closing_node():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node, ret, mess = exec_node("node1")
    if ret == 1:
        close_node(node)
        return 1, mess

    close_node(node)

    node, ret, mess = exec_node("node1")
    close_node(node)
    return ret, mess


def test_open_close_with_node_open():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node1, ret1, mess1 = exec_node("node1")
    if ret1 == 1:
        close_node(node1)
        return 1, mess1

    node2, ret2, mess2 = exec_node("node2")

    close_node(node1)

    node3, ret3, mess3 = exec_node("node1")
    if ret3 == 1:
        close_nodes([node3, node2])
        return 1, mess3

    close_nodes([node3, node2])
    return ret2, mess2


def test_stress_open_close():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    for i in range(0, 100):
        proc, ret, mess = exec_node("node1")
        close_node(proc)

        if ret != 0:
            return ret, mess

    return 0, ""


def test_stress_simultaneous():
    proc_array = []

    for port in range(2121, 2121 + 60, 2):
        status, output = getstatusoutput(
            "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:" + str(port) + ":" + str(port + 1))
        if status != 0:
            return 1, "ERROR: Configuration files could not be created."

        proc, ret, mess = exec_node("node1")
        proc_array.append(proc)

        if ret != 0:
            for proc in proc_array:
                close_node(proc)

            return ret, mess

    for proc in proc_array:
        close_node(proc)

    return 0, ""


# MASTER TESTS
def test_master_one_node(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2131:2132")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc, node_ret, node_mess = exec_node("node1")
    if node_ret == 1:
        close_node(node_proc)
        return 1, node_mess

    master, master_ret, master_mess = exec_master(master_args, master_name)

    close_node(node_proc)
    close_master(master)
    return master_ret, master_mess


def test_master_two_nodes(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_node(node_proc1)
        close_node(node_proc2)
        return 1, node_mess2

    master, master_ret, master_mess = exec_master(master_args, master_name)

    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_master_twice(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret, master_mess

    master, master_ret, master_mess = exec_master(master_args, master_name)

    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_three_nodes_one_down(master_args, master_name):
    node_info = " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 127.0.0.1:2125:2126"
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + node_info)
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    node_proc3, node_ret3, node_mess3 = exec_node("node3")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2, node_proc3])
        return 1, node_mess3

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        close_nodes([node_proc1, node_proc2, node_proc3])

        return master_ret, master_mess

    close_node(node_proc3)

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_insuff_threshold_bordercase(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 -ct -th 0")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc, node_ret, node_mess = exec_node("node1")
    if node_ret == 1:
        close_node(node_proc)
        return 1, node_mess

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        close_node(node_proc)
        return master_ret, master_mess

    close_node(node_proc)

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        return 0, ""
    else:
        return 1, "FAILURE: The master should not be able to sign."


def test_insuff_threshold(master_args, master_name):
    node_info = " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 127.0.0.1:2125:2126"
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + node_info + "-ct -th 3")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    node_proc3, node_ret3, node_mess3 = exec_node("node3")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2, node_proc3])
        return 1, node_mess3

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret, master_mess

    close_node(node_proc3)

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_nodes([node_proc1, node_proc2])
    close_master(master)

    if master_ret != 0:
        return 0, ""
    else:
        return 1, "FAILURE: The master should not be able to sign."


def test_three_nodes_two_open(master_args, master_name):
    node_info = " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 127.0.0.1:2125:2126"
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + node_info)
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_master_stress_open_close(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master = None
    for i in range(0, 10):
        master, master_ret, master_mess = exec_master(master_args, master_name)
        close_master(master)

        if master_ret != 0:
            close_nodes([node_proc1, node_proc2])
            return master_ret, master_mess

    close_nodes([node_proc1, node_proc2])
    return 0, ""


def test_stress_multiple_masters(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 -m 10")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    for i in range(1, 11):
        master, master_ret, master_mess = exec_master(
            master_args, master_name, "cryptoki" + str(i) + ".conf")
        close_master(master)

        if master_ret != 0:
            close_nodes([node_proc1, node_proc2])
            return master_ret, master_mess

    close_nodes([node_proc1, node_proc2])
    return 0, ""


def test_cryptoki_wout_key():
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    dummy_file = create_dummy_file()
    master_args = [join(
                   EXEC_PATH,
                   "tests/system_test/pkcs_11_test"),
                   "-cf",
                   dummy_file.name,
                   "-p",
                   "1234"]
    master_name = "pkcs_11_test"
    master, master_ret, master_mess = exec_master(master_args, master_name)
    close_master(master)

    if master_ret != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret, master_mess

    master_args = [join(
                   EXEC_PATH,
                   "tests/system_test/pkcs_11_test"),
                   "-f",
                   dummy_file.name,
                   "-p",
                   "1234"]
    master_name = "pkcs_11_test"
    master, master_ret, master_mess = exec_master(master_args, master_name)
    dummy_file.close()

    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_two_masters_one_nodes(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 -m 2")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    master, master_ret, master_mess = exec_master(
        master_args, master_name, "cryptoki1.conf")
    close_master(master)

    if master_ret != 0:
        close_node(node_proc1)
        return master_ret, master_mess

    master, master_ret, master_mess = exec_master(
        master_args, master_name, "cryptoki2.conf")

    close_node(node_proc1)
    close_master(master)
    return master_ret, master_mess


def test_two_masters_two_nodes(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 -m 2")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master, master_ret, master_mess = exec_master(
        master_args, master_name, "cryptoki1.conf")
    close_master(master)

    if master_ret != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret, master_mess

    master, master_ret, master_mess = exec_master(
        master_args, master_name, "cryptoki2.conf")

    close_nodes([node_proc1, node_proc2])
    close_master(master)
    return master_ret, master_mess


def test_two_masters_simultaneous(master_args, master_name):
    status, output = getstatusoutput(
        "python " + CONFIG_CREATOR_PATH + " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 -m 2")
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master1, master_ret1, master_mess1 = exec_master(
        master_args, master_name, "cryptoki1.conf")
    master2, master_ret2, master_mess2 = exec_master(
        master_args, master_name, "cryptoki2.conf")

    if master_ret1 != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret1, master_mess1

    if master_ret2 != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret2, master_mess2

    close_nodes([node_proc1, node_proc2])
    close_master(master1)
    close_master(master2)
    return 0, ""


def test_two_masters_thres2_nodes3(master_args, master_name):
    info = " 127.0.0.1:2121:2122 127.0.0.1:2123:2124 127.0.0.1:2125:2126 -m 2"
    status, output = getstatusoutput("python " + CONFIG_CREATOR_PATH + info)
    if status != 0:
        return 1, "ERROR: Configuration files could not be created."

    node_proc1, node_ret1, node_mess1 = exec_node("node1")
    if node_ret1 == 1:
        close_node(node_proc1)
        return 1, node_mess1

    node_proc2, node_ret2, node_mess2 = exec_node("node2")
    if node_ret2 == 1:
        close_nodes([node_proc1, node_proc2])
        return 1, node_mess2

    master1, master_ret1, master_mess1 = exec_master(
        master_args, master_name, "cryptoki1.conf")
    close_master(master1)

    if master_ret1 != 0:
        close_nodes([node_proc1, node_proc2])
        return master_ret1, master_mess1

    master2, master_ret2, master_mess2 = exec_master(
        master_args, master_name, "cryptoki2.conf")

    close_nodes([node_proc1, node_proc2])
    close_master(master2)
    return master_ret2, master_mess2


# INTERFACES FOR DIFFERENT TESTS
def perform_test_on_pkcs11(test):
    dummy_file = create_dummy_file()
    master_args = [join(
                   EXEC_PATH,
                   "tests/system_test/pkcs_11_test"),
                   "-cf",
                   dummy_file.name,
                   "-p",
                   "1234"]
    ret, mess = test(master_args, "pkcs_11_test")

    dummy_file.close()
    return ret, mess


def perform_test_on_dtc(test):
    config_path = join(DUMP, "master.conf")
    master_args = [join(
                   EXEC_PATH,
                   "tests/system_test/dtc_master_test"),
                   config_path]

    return test(master_args, "dtc_master_test")


def pretty_print(index, name, result, mess, runtime, verbosity):
    if result == 0:
        if verbosity:
            print str(index) + ".- " + name + " passed! Run time: " + str(runtime)[:6] + " seconds."
    else:
        print str(index) + ".- " + name + " failed!"
        print "      " + str(mess)


def main(argv=None):
    global NODE_TIMEOUT
    global MASTER_TIMEOUT

    parser = argparse.ArgumentParser(description="System Testing")
    parser.add_argument("build_path",
                        help="path of the folder where the project is build",
                        type=str)
    parser.add_argument("-v",
                        "--verbosity",
                        help="specify this if you want to see every running test",
                        default=False,
                        action="store_true")
    parser.add_argument("-s",
                        "--store_failed_dumps",
                        help="specify this if you want to save dump folders",
                        default=False,
                        action="store_true")
    parser.add_argument("-nt",
                        "--node_timeout",
                        help="maximum time for nodes to respond (default: " + str(
                            NODE_TIMEOUT) + " seg)",
                        default=NODE_TIMEOUT,
                        type=int)
    parser.add_argument("-mt",
                        "--master_timeout",
                        help="maximum time for masters to respond (default: " + str(
                            MASTER_TIMEOUT) + " seg)",
                        default=MASTER_TIMEOUT,
                        type=int)
    parser.add_argument("-ws",
                        "--with_stress_tests",
                        help="specify this if you want to add stress tests to the test case",
                        default=False,
                        action="store_true")
    parser.add_argument("-dp",
                        "--dump_path",
                        help="specify whether you would like to change to path of the dump files",
                        default=DEFAULT_DUMP_PATH,
                        type=str)
    args = parser.parse_args()

    global CONFIG_CREATOR_PATH
    script_path = split(abspath(__file__))[0]
    CONFIG_CREATOR_PATH = join(
        script_path,
        "..",
     "..",
     "scripts",
     "create_config.py")

    NODE_TIMEOUT = args.node_timeout
    MASTER_TIMEOUT = args.master_timeout

    global EXEC_PATH
    EXEC_PATH = abspath(args.build_path)

    print(" --- Testing starting --- \n")

    tests = [("TEST ONE NODE", test_one_node, None),
             ("TEST TWO NODE", test_two_nodes, None),
             ("TEST OPEN CLOSED NODE", test_opening_closing_node, None),
             ("TEST OPEN CLOSE w/ NODE OPEN",
              test_open_close_with_node_open, None),
             ("TEST PKCS11 ONE NODE",
              perform_test_on_pkcs11, test_master_one_node),
             ("TEST PKCS11 TWO NODES",
              perform_test_on_pkcs11, test_master_two_nodes),
             ("TEST DTC ONE NODE", perform_test_on_dtc, test_master_one_node),
             ("TEST DTC TWO NODES", perform_test_on_dtc,
              test_master_two_nodes),
             ("TEST PKCS11 RUN TWICE",
              perform_test_on_pkcs11, test_master_twice),
             ("TEST DTC RUN TWICE", perform_test_on_dtc, test_master_twice),
             ("TEST PKCS11 THREE NODES, ONE FALLS",
              perform_test_on_pkcs11, test_three_nodes_one_down),
             ("TEST DTC THREE NODES, ONE FALLS",
              perform_test_on_dtc, test_three_nodes_one_down),
             ("TEST PKCS11 THREE NODES, TWO OPEN",
              perform_test_on_pkcs11, test_three_nodes_two_open),
             ("TEST DTC THREE NODES, TWO OPEN",
              perform_test_on_dtc, test_three_nodes_two_open),
             ("TEST PKCS11 INSUFF THRESHOLD BORDER CASE",
              perform_test_on_pkcs11, test_insuff_threshold_bordercase),
             ("TEST DTC INSUFF THRESHOLD BORDER CASE",
              perform_test_on_dtc, test_insuff_threshold_bordercase),
             ("TEST PKCS11 INSUFFICIENT THRESHOLD",
              perform_test_on_pkcs11, test_insuff_threshold),
             ("TEST DTC INSUFFICIENT THRESHOLD",
              perform_test_on_dtc, test_insuff_threshold),
             ("TEST PKCS11 TWO MASTERS ONE NODE",
              perform_test_on_pkcs11, test_two_masters_one_nodes),
             ("TEST DTC TWO MASTERS ONE NODE",
              perform_test_on_dtc, test_two_masters_one_nodes),
             ("TEST PKCS11 TWO MASTERS TWO NODE",
              perform_test_on_pkcs11, test_two_masters_two_nodes),
             ("TEST DTC TWO MASTERS TWO NODE",
              perform_test_on_dtc, test_two_masters_two_nodes),
             ("TEST PKCS11 MASTERS SIMULTANEOUS",
              perform_test_on_pkcs11, test_two_masters_simultaneous),
             ("TEST DTC MASTERS SIMULTANEOUS",
              perform_test_on_dtc, test_two_masters_simultaneous),
             ("TEST PKCS11 MASTERS:2 THRES:2 NODES:3",
              perform_test_on_pkcs11, test_two_masters_thres2_nodes3),
             ("TEST DTC  MASTERS:2 THRES:2 NODES:3",
              perform_test_on_dtc, test_two_masters_thres2_nodes3),
             ("TEST PKCS11 SAME DATABASE", test_cryptoki_wout_key, None)]

    stress_tests = [("NODE STRESS OPEN CLOSE", test_stress_open_close, None),
                    ("NODE STRESS SIMULTANEOUS",
                     test_stress_simultaneous, None),
                    ("PKCS11 STRESS SAME NODE", perform_test_on_pkcs11,
                     test_master_stress_open_close),
                    ("DTC STRESS SAME NODE", perform_test_on_dtc,
                     test_master_stress_open_close),
                    ("PKCS11 STRESS MULTIPLE MASTERS",
                     perform_test_on_pkcs11, test_stress_multiple_masters),
                    ("DTC STRESS MULTIPLE MASTERS", perform_test_on_dtc, test_stress_multiple_masters)]

    if args.with_stress_tests:
        tests.extend(stress_tests)

    tests_passed = 0
    tests_runned = len(tests)
    total_time = 0

    dump_path = abspath(args.dump_path)
    if not exists(dump_path):
        print "ERROR: Dump path doesn't exists >> " + dump_path

    for index, test in zip(range(1, len(tests) + 1), tests):
        global DUMP
        dump_prefix = "libdtc_test_" + str(index) + "_"
        DUMP = mkdtemp(prefix=dump_prefix, dir=dump_path)
        chdir(DUMP)

        name, func, func_args = test

        start = time()

        if func_args is None:
            result, mess = func()
        else:
            result, mess = func(func_args)

        end = time()
        total_time += end - start

        chdir("..")
        if result == 0:
            tests_passed += 1
            erase_dump()

        if not args.store_failed_dumps:
            erase_dump()

        pretty_print(index, name, result, mess, end - start, args.verbosity)

    test_percentage = str(
        100 * float(tests_passed) / float(tests_runned))[:5] + "%"
    passing_string = "|" * tests_passed + " " * (tests_runned - tests_passed)
    print("\n --- Tests passed " + str(tests_passed) + "/" + str(tests_runned)
          + " (" + test_percentage + "): [" + passing_string + "] ---")
    print(" --- Total run time: " + str(total_time)[:6] + " seconds ---")

    return tests_runned - tests_passed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
