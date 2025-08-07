#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to define all possible states of our environment, the Kisshome IDS system
"""

import json

from threading import Lock

# Define the name of our environment
ENV_NAME = "KISSHOME IDS"
# State file saving the current state
STATE_FILE = "/config/state.json" 
# Lock the file access
LOCK = Lock()
# Define the states of our environment
STARTED = "Started"
RUNNING = "Running"
CONFIGURING = "Configuring"
ANALYZING = "Analyzing"
EXITED = "Exited"


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