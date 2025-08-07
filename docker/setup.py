#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to set the pipes in the docker container up
"""

import os

# Rule based (rb) pcap and result pipes
RB_PCAP_PIPE = os.path.join("/pipe", "rb_pcap_pipe")
RB_RESULT_PIPE = os.path.join("/pipe", "rb_result_pipe")
# Machine learning (ml) pcap and result pipes
ML_PCAP_PIPE = os.path.join("/pipe", "ml_pcap_pipe")
ML_RESULT_PIPE = os.path.join("/pipe", "ml_result_pipe")


def set_pcap_pipes():
    """
    Set the pcap pipes for the Kisshome IDS environment up

    @return: paths of the created pipes
    """
    # Ensure the named pipes exists
    if not os.path.exists(RB_PCAP_PIPE):
        os.mkfifo(RB_PCAP_PIPE)
    if not os.path.exists(ML_PCAP_PIPE):
        os.mkfifo(ML_PCAP_PIPE)
    return RB_PCAP_PIPE, ML_PCAP_PIPE


def set_result_pipes():
    """
    Set the result pipes for the Kisshome IDS environment up

    @return: paths of the created pipes
    """
    # Ensure the named pipes exists
    if not os.path.exists(RB_RESULT_PIPE):
        os.mkfifo(RB_RESULT_PIPE)
    if not os.path.exists(ML_RESULT_PIPE):
        os.mkfifo(ML_RESULT_PIPE)
    return RB_RESULT_PIPE, ML_RESULT_PIPE
    

#if __name__ == '__main__':
    #set_pcap_pipes()
    #set_result_pipes()