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