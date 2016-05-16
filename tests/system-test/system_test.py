#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from os.path import exists
from tempfile import mkdtemp
import shutil

"""

"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"

DUMP = ""


def erase_dump():
    if exists(DUMP):
        shutil.rmtree(DUMP)
    return 0


def test_one_node():
    pass


def main(argv=None):
    global DUMP
    DUMP = mkdtemp(dir="../")

    test_one_node()

    erase_dump()
    return 0


if __name__ == "__main__":
    main(sys.argv)