#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from os.path import exists
from tempfile import mkdtemp
import shutil
from commands import getstatusoutput
import subprocess
from threading import Timer
from shlex import split

"""

"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"

DUMP = ""

NODE_RDY = "Both socket binded, node ready to talk with the Master."

TEST_TIMEOUT = 10


def erase_dump():
    if exists(DUMP):
        shutil.rmtree(DUMP)
    return 0


def test_one_node():
    getstatusoutput("python ../../scripts/create_config.py 127.0.0.1:3001:3002 -o " + DUMP)

    proc = subprocess.Popen(["/home/danielaviv/install/bin/node", "-c", DUMP + "/node1.conf"], stderr=subprocess.PIPE)
    timer = Timer(TEST_TIMEOUT, proc.kill)

    stdout_lines = iter(proc.stderr.readline, "")
    for stdout_line in stdout_lines:
        if NODE_RDY in stdout_line:
            proc.stderr.close()
            proc.terminate()
            return 0

    proc.stderr.close()
    proc.terminate()
    return 1


def test_two_nodes():
    return 1


def main(argv=None):
    global DUMP
    DUMP = mkdtemp(dir="./")

    print "OUTPUT: " + str(test_one_node())

    erase_dump()
    return 0


if __name__ == "__main__":
    main(sys.argv)