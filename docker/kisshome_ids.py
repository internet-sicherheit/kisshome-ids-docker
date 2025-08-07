#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Class for the Kisshome IDS
"""

import logging

from logging.handlers import TimedRotatingFileHandler
from multiprocessing import *
from setup import *
from rb_analysis import *
from ml_analysis_multiprocess import *
from aggregator import *
from states import set_state, STARTED, EXITED

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
# Rotate files each day to max 7 files, oldest will be deleted
fh = TimedRotatingFileHandler(filename="/shared/kisshome_ids.log", when='D', interval=1, backupCount=7, encoding='utf-8', delay=False)
sh = logging.StreamHandler()
fh.setLevel(logging.DEBUG)  # set the log level for the log file
fh.setFormatter(formatter)
sh.setFormatter(formatter)
sh.setLevel(logging.INFO)  # set the log level for the console
default_logger = logging.getLogger(__name__)
default_logger.addHandler(fh)
default_logger.addHandler(sh)
default_logger.setLevel(logging.INFO)
default_logger.propagate = False


class KisshomeIDS:
    """Our IDS system"""
    def __init__(self, logger=default_logger):
        """
        Init

        @param logger: logger for logging, default default_logger
        @return: nothing
        """
        # Use init param first
        self.logger = logger
        
        # Create class variables to save configs
        self.pcap_name = ""
        self.allow_training = False
        self.callback_url = ""

        # Create a list for processes to control them while the IDS is running
        self.analysis_processes = []
        self.aggregation_processes = []

        # Create and set all pipe paths
        self.rb_pcap_pipe, self.ml_pcap_pipe = set_pcap_pipes()
        self.rb_result_pipe, self.ml_result_pipe = set_result_pipes()

        # Configure the processes to set everything up and enable all API endpoints
        self.configure_analysis()
        self.configure_aggregation()

        # Start deamon for the rb component
        rb_start_deamon()

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

        # Recreate aggregation process
        self.configure_aggregation()

        self.logger.debug(f"{pcap_name=}")
        self.logger.info("Updated pcap name")

    def update_configuration(self, callback_url, allow_training):
        """
        Update the configuration params of our IDS environment

        @param callback_url: URL of the adapter for receiving the results
        @param allow_training: a var to check if the user allows training
        @return: nothing
        """
        # Stop analysis first since there are writing processes on the pipe
        self.stop_analysis()
        self.stop_aggregation()

        # meta_json handled in API
        self.callback_url = callback_url
        self.allow_training = allow_training

        # Recreate all processes, but don't start automatically
        self.configure_analysis()
        self.configure_aggregation()

        self.logger.debug(f"{callback_url=}, {allow_training=}")
        self.logger.info("Updated configuration")

    def configure_analysis(self):
        """
        Create and configure the processes for the analysis in our IDS environment

        @return: nothing
        """
        try:
            # Create new processes for the analysis
            rb_process = Process(target=rb_analyze, name="rb_process", args=(self.rb_pcap_pipe, self.rb_result_pipe))
            self.analysis_processes.append(rb_process)

            ml_process = Process(target=ml_analyze, name="ml_process", args=(self.ml_pcap_pipe, self.ml_result_pipe, self.allow_training))
            self.analysis_processes.append(ml_process)

            self.logger.info("Analysis configured")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)

    def configure_aggregation(self):
        """
        Create and configure the process for the aggregation in our IDS environment

        @return: nothing
        """
        try:
            # Create new process for the aggregation
            aggregate_process = Process(target=aggregate, name="aggregate_process", args=(self.rb_result_pipe, self.ml_result_pipe, self.callback_url, self.pcap_name))
            self.aggregation_processes.append(aggregate_process)

            self.logger.info("Aggregation configured")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)

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

            self.logger.info("Analysis started")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)

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

            self.logger.info("Aggregation started")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)

    def stop_analysis(self):
        """
        Stop and configure the processes for the analysis in our IDS environment

        @return: nothing        
        """
        try:
            # Check if the processes are alive before killing them
            for analysis_process in self.analysis_processes:
                if analysis_process.is_alive():
                    analysis_process.kill()
                    analysis_process.join()

            # Also clear list
            self.analysis_processes = []

            self.logger.info("Analysis stopped")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)
                
    def stop_aggregation(self):
        """
        Stop the process for the aggregation in our IDS environment

        @return: nothing
        """
        try:
            # Check if the process is alive before killing it
            for aggregation_process in self.aggregation_processes:
                if aggregation_process.is_alive():
                    aggregation_process.kill()
                    aggregation_process.join()

            # Also clear list
            self.aggregation_processes = []

            self.logger.info("Aggregation stopped")
        except Exception as e:
            self.logger.exception(e)
            set_state(EXITED)
