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
Class for the Kisshome IDS
"""

import glob
import logging

from logging.handlers import TimedRotatingFileHandler
from multiprocessing import *
from setup import *
from rb_analysis import *
from ml_analysis import *
from aggregator import *
from states import set_state, STARTED, ERROR

LOG_DIR = "/shared/logs"
LOG_NAME = "kisshome_ids.log"

def setup_logging(logname):
    """
    Set up a logger with a name

    @param logname: name of the log file handler
    @return: logger object
    """
    # Ensure that the log directory exist and old files are deleted
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, logname)
    for old_log in glob.glob(f"{log_path}.*"):
        os.remove(old_log)
    # Each log line includes the date and time, the log level, the current function and the message
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
    # The log file is the same as the module name plus the suffix ".log"
    # Rotate files each day to max 7 files, oldest will be deleted
    fh = TimedRotatingFileHandler(filename=log_path, when='D', interval=1, backupCount=7, encoding='utf-8', delay=False, utc=False)
    sh = logging.StreamHandler()
    fh.setLevel(logging.DEBUG)  # set the log level for the log file
    fh.setFormatter(formatter)
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)  # set the log level for the console
    default_logger = logging.getLogger(logname)
    default_logger.addHandler(fh)
    default_logger.addHandler(sh)
    default_logger.setLevel(logging.INFO)
    default_logger.propagate = False
    # Return logger
    return default_logger


class KisshomeIDS:
    """Our IDS system"""
    def __init__(self):
        """
        Init

        @return: nothing
        """
        # First create own logger and then logger for the different processes
        self.logger = setup_logging(LOG_NAME)

        self.rb_logger = setup_logging("rb_analysis.log")
        self.ml_logger = setup_logging("ml_analysis.log")
        self.aggregator_logger = setup_logging("aggregator.log")
        
        # Create class variables to save configs
        self.pcap_name = ""
        self.allow_training = False
        self.callback_url = ""
        self.save_threshold_seconds = ""

        # Set path and dir for the .json files
        self.meta_json = os.path.join("/config", "meta.json")
        if not os.path.exists(self.meta_json):
            os.makedirs(os.path.dirname(self.meta_json), exist_ok=True) # Should exist, but be safe
            with open(self.meta_json, "w") as meta_file:
                json.dump({}, meta_file)
        
        self.training_json = os.path.join("/shared/ml", "training_progress.json")
        if not os.path.exists(self.training_json):
            os.makedirs(os.path.dirname(self.training_json), exist_ok=True) # Can exist, but be safe
            with open(self.training_json, "w") as training_file:
                json.dump({}, training_file)

        # Create and set all pipe paths
        self.rb_pcap_pipe, self.ml_pcap_pipe = set_pcap_pipes()
        self.rb_result_pipe, self.ml_result_pipe = set_result_pipes()

        # Create a list for processes to control them while the IDS is running
        self.analysis_processes = []
        self.aggregation_processes = []

        # Configure the processes to set everything up and enable all API endpoints
        self.configure_analysis()
        self.configure_aggregation()

        try:
            # Start daemon for the rb component
            rb_start_daemon(self.rb_logger)
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)

        # Set IDS started
        set_state(STARTED)

        self.logger.debug("Init done")
        
    def update_pcap_name(self, pcap_name):
        """
        Update the name of the pcap

        @param pcap_name: new pcap name as a string
        @return: nothing
        """
        # Only reconfigure aggregator since NO analysis is running when this is called
        self.stop_aggregation()

        self.pcap_name = pcap_name
        self.logger.info("Update pcap name for aggregation")

        # Recreate aggregation process
        self.configure_aggregation()

        self.logger.debug(f"{pcap_name=}")
        self.logger.info("Updated pcap name")

    def update_configuration(self, callback_url, save_threshold_seconds, allow_training):
        """
        Update the configuration params of our IDS environment

        @param callback_url: URL of the adapter for receiving the results
        @param save_threshold_seconds: interval in seconds between each regular analysis attempt set by the user
        @param allow_training: a var to check if the user allows training
        @return: nothing
        """
        # Stop analysis first since there are writing processes on the pipe
        self.stop_analysis()
        self.stop_aggregation()

        # meta_json handled in API
        self.callback_url = callback_url
        self.save_threshold_seconds = save_threshold_seconds
        self.allow_training = allow_training

        # Recreate all processes, but don't start automatically
        self.configure_analysis()
        self.configure_aggregation()

        self.logger.debug(f"{callback_url=}, {save_threshold_seconds=}, {allow_training=}")
        self.logger.info("Updated configuration")

    def configure_analysis(self):
        """
        Create and configure the processes for the analysis in our IDS environment

        @return: nothing
        """
        try:
            # Create new processes for the analysis
            rb_process = Process(target=rb_analyze, name="rb_process", args=(self.rb_logger, self.rb_pcap_pipe, self.rb_result_pipe, self.meta_json))
            self.analysis_processes.append(rb_process)

            ml_process = Process(target=ml_analyze, name="ml_process", args=(self.ml_logger, self.ml_pcap_pipe, self.ml_result_pipe, self.meta_json, self.allow_training, self.training_json))
            self.analysis_processes.append(ml_process)

            self.logger.debug(f"{rb_process=}, {ml_process=}")
            self.logger.info("Analysis configured")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)

    def configure_aggregation(self):
        """
        Create and configure the process for the aggregation in our IDS environment

        @return: nothing
        """
        try:
            # Create new process for the aggregation
            aggregate_process = Process(target=aggregate, name="aggregate_process", args=(self.aggregator_logger, self.rb_result_pipe, self.ml_result_pipe, self.callback_url, self.save_threshold_seconds, self.allow_training, self.pcap_name))
            self.aggregation_processes.append(aggregate_process)

            self.logger.debug(f"{aggregate_process=}")
            self.logger.info("Aggregation configured")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)

    def start_analysis(self):
        """
        Start the processes for the analysis in our IDS environment

        @return: nothing
        """
        try:
            # Only start when the processes are not running
            for analysis_process in self.analysis_processes:
                if not analysis_process.is_alive():
                    analysis_process.start()

            self.logger.debug(f"{analysis_process=}")
            self.logger.info("Analysis started")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)

    def start_aggregation(self):
        """
        Start the process for the aggregation in our IDS environment

        @return: nothing
        """
        try:
            # Only start when the process is not running
            for aggregation_process in self.aggregation_processes:
                if not aggregation_process.is_alive():
                    aggregation_process.start()

            self.logger.debug(f"{aggregation_process=}")
            self.logger.info("Aggregation started")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)

    def stop_analysis(self):
        """
        Stop and configure the processes for the analysis in our IDS environment

        @return: nothing        
        """
        try:
            # Check if the processes are alive before killing them
            self.logger.debug(f"{self.analysis_processes=}")
            for analysis_process in self.analysis_processes:
                if analysis_process.is_alive():
                    analysis_process.kill()
                    analysis_process.join()

            # Also clear list
            self.analysis_processes = []

            self.logger.info("Analysis stopped")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)
                
    def stop_aggregation(self):
        """
        Stop the process for the aggregation in our IDS environment

        @return: nothing
        """
        try:
            # Check if the process is alive before killing it
            self.logger.debug(f"{self.aggregation_processes=}")
            for aggregation_process in self.aggregation_processes:
                if aggregation_process.is_alive():
                    aggregation_process.kill()
                    aggregation_process.join()

            # Also clear list
            self.aggregation_processes = []

            self.logger.info("Aggregation stopped")
        except Exception as e:
            self.logger.exception(f"IDS error: {e}")
            set_state(ERROR)
