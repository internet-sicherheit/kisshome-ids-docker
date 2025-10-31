#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2025 if(is)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Script to define all possible states of our environment, the Kisshome IDS system
"""

import json

from filelock import FileLock

# Define the name of our environment
ENV_NAME = "KISSHOME IDS"
# State file saving the current state
STATE_FILE = "/config/state.json" 
# Lock the file access
LOCK = FileLock(f"{STATE_FILE}.lock")
# Define the states of our environment
STARTED = "Started"
RUNNING = "Running"
CONFIGURING = "Configuring"
ANALYZING = "Analyzing"
ERROR = "Error"


def get_state():
    """
    Get the state of our IDS environment

    @return: current state as a string
    """
    with LOCK:
        with open(STATE_FILE, "r") as state_file:
            return json.load(state_file)["state"]


def set_state(new_state):
    """
    Set and update the state of our IDS environment

    @param new_state: new state as a string
    @return: nothing
    """
    with LOCK:
        with open(STATE_FILE, "w") as state_file:
            json.dump({"state": new_state}, state_file)