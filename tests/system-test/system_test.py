#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from os.path import exists, abspath, isdir
from tempfile import mkdtemp
import shutil
from commands import getstatusoutput
import subprocess
from threading import Timer
import argparse

"""

"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"

DUMP = ""
NODE_EXEC = ""

NODE_RDY = "Both socket binded, node ready to talk with the Master."
TEST_TIMEOUT = 10


def erase_dump():
    if exists(DUMP):
        shutil.rmtree(DUMP)
    return 0


def exec_node(config):
    if not isdir(NODE_EXEC + "/bin"):
        return None, 1, "FAILURE: Path doesn't exists >> " + NODE_EXEC + "/bin"

    node = subprocess.Popen([NODE_EXEC + "/bin/node", "-c", DUMP + "/" + config + ".conf"], stderr=subprocess.PIPE)
    timer = Timer(TEST_TIMEOUT, node.kill)

    stdout_lines = iter(node.stderr.readline, "")
    for stdout_line in stdout_lines:
        if NODE_RDY in stdout_line:
            node.stderr.close()
            node.terminate()
            return node, 0, ""

    return node, 1, "FAILURE: Node was unable to get ready"


def test_one_node():
    getstatusoutput("python ../../scripts/create_config.py 127.0.0.1:2121:2122 -o " + DUMP)
    proc, ret, mess = exec_node("node1")

    if proc is not None:
        proc.stderr.close()
        proc.terminate()

    return ret, mess


def test_two_nodes():
    getstatusoutput("python ../../scripts/create_config.py 127.0.0.1:2121:2122 127.0.0.1:2123:2124 -o " + DUMP)

    node1, ret1, mess1 = exec_node("node1")
    if ret1 == 1:
        return 1, mess1

    node2, ret2, mess2 = exec_node("node2")

    if node1 is not None:
        node1.stderr.close()
        node1.terminate()

    if node2 is not None:
        node2.stderr.close()
        node2.terminate()

    return ret2, mess2


def test_opening_closing_node():
    getstatusoutput("python ../../scripts/create_config.py 127.0.0.1:2121:2122 -o " + DUMP)

    node, ret, mess = exec_node("node1")
    if ret == 1:
        return 1, mess

    if node is not None:
        node.stderr.close()
        node.terminate()

    node, ret, mess = exec_node("node1")
    return ret, mess


def test_fail():
    return 1, "FAILURE: This is suppose to fail"


def pretty_print(index, name, result, mess, verbosity):
    if result == 0:
        if verbosity:
            print str(index) + " .- " + name + " passed!"
    else:
        print str(index) + " .- " + name + " failed!"
        print "      " + str(mess)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="System Testing")
    parser.add_argument("node_exec",
                        help="path of the bin folder where node executable is",
                        type=str)
    parser.add_argument("-v",
                        "--verbosity",
                        help="specify this if you want to see every running test",
                        default=False,
                        action="store_true")
    args = parser.parse_args()

    global DUMP
    DUMP = mkdtemp(dir="./")

    global NODE_EXEC
    NODE_EXEC = abspath(args.node_exec)

    print(" --- Testing commencing --- \n")
    tests = [("TEST ONE NODE", test_one_node),
             ("TEST TWO NODE", test_two_nodes),
             ("TEST OPEN CLOSED NODE", test_opening_closing_node),
             ("TEST FAIL", test_fail)]

    tests_passed = 0
    tests_runned = len(tests)

    for index, test in zip(range(1, len(tests) + 1), tests):
        name, func = test
        result, mess = func()

        if result == 0:
            tests_passed += 1

        pretty_print(index, name, result, mess,  args.verbosity)

    passing_string = "|"*tests_passed + " "*(tests_runned-tests_passed)
    print("\n --- Tests passed " + str(tests_passed) + "/" + str(tests_runned) + ": [" + passing_string + "] ---")
    erase_dump()
    return 0


if __name__ == "__main__":
    main(sys.argv)
