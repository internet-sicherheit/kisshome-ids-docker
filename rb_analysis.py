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
Script to analyze the .pcap files with suricata
"""

import os
import glob
import setproctitle
import logging
import json
import subprocess
import time
import tempfile
import schedule
import psutil
import signal

from logging.handlers import TimedRotatingFileHandler
from states import set_state, ERROR

LOG_DIR = "/shared/logs"
LOG_NAME = "rb_analysis.log"

def setup_logger():
    """
    Set up a logger

    @return: logger object
    """
    # Ensure that the log directory exist and old files are deleted
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, LOG_NAME)
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
    default_logger = logging.getLogger(__name__)
    default_logger.addHandler(fh)
    default_logger.addHandler(sh)
    default_logger.setLevel(logging.INFO)
    default_logger.propagate = False
    # Return logger
    return default_logger


# Use the default log directory provided by the .yaml file
SURICATA_YAML_DIRECTORY = "/var/log/suricata"
# Socket created by the suricata daemon
# Also provide the default path
RB_SOCKET = "/var/run/suricata/suricata-command.socket"
# Path to meta.json
META_JSON = None
# Attempts before throwing an error
MAX_RETRIES = 5


logger = None 


def rb_start_daemon(rb_logger):
    """
    Start Suricata by using its daemon feature
    
    @param rb_logger: logger for logging
    @return: nothing
    """
    # Set up logger
    global logger 
    if not logger:
        if rb_logger:
            logger = rb_logger
        else:
            logger = setup_logger()
    try:
        # Only start when there is no suricata process running by checking for a .pid file
        daemon_pid_file = "/var/run/suricata.pid"
        if not os.path.exists(daemon_pid_file):
            # Prepare rules for the initial startup
            if rb_prepare_rules():
                # Remove leftovers like old sockets
                global RB_SOCKET
                if os.path.exists(RB_SOCKET):
                    os.remove(RB_SOCKET)
                cmd = f"suricata -c /config/suricata.yaml --unix-socket -D"
                logger.debug(f"Invoking Suricata daemon with {cmd=}")
                suricatad_process = subprocess.run(cmd, capture_output=True, shell=True)
                if suricatad_process.returncode != 0:
                    # Something went wrong
                    logger.error(f"Suricata daemon process had a non zero exit code: {suricatad_process}")
                    raise Exception(suricatad_process) 
                else:
                    is_ready = False
                    while not is_ready:
                        # Use the file provided in the .yaml
                        with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "r") as log_file:
                            for log_line in log_file.readlines():
                                if "unix socket" in log_line:
                                    socket = str(log_line).split("'")[1] # Parse socket name from line
                                    if RB_SOCKET != socket:
                                        RB_SOCKET = socket
                                    logger.debug(f"Socket created at: {RB_SOCKET}")
                                if "Engine started" in log_line:
                                    is_ready = True # daemon has created socket and started engine
                                    break
                    logger.info(f"Suricata daemon started: {suricatad_process}")
            else:
                logger.warning("Suricata rule preparation failed")
        else:
            try:
                # Handle a docker restart
                daemon_pid = 0
                with open(daemon_pid_file, "r") as daemon_file:
                    daemon_pid = int(daemon_file.read().strip()) # File has only process id 
                logger.debug(f"Suricata daemon already running with pid={daemon_pid}, kill and restart it")
                # Kill any existing daemon, remove .pid file and call function again
                if not psutil.pid_exists(daemon_pid):
                    logger.debug(f"No daemon process with pid={daemon_pid}")
                else:
                    daemon_process = psutil.Process(daemon_pid)
                    # Double-check before killing 
                    if "suricata" in daemon_process.name().lower():
                        os.kill(daemon_pid, signal.SIGKILL)
                        logger.debug(f"Killed existing {daemon_process.name()} with pid={daemon_pid}")       
            except (ProcessLookupError, psutil.NoSuchProcess):
                logger.debug("Invalid or dead daemon process, skipping...")
                pass
            finally:
                os.remove(daemon_pid_file)
                logger.info(f"Killed and removed existing Suricata daemon process with pid={daemon_pid}, start new daemon")
                # Restart daemon
                rb_start_daemon(rb_logger)      
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not start Suricata daemon: {e}")


def rb_test_daemon(rb_logger):
    """
    Test Suricata daemon by sending the version command 
    
    @param rb_logger: logger for logging
    @return: nothing
    """
    # Test daemon
    global MAX_RETRIES
    cmd = f"suricatasc {RB_SOCKET} -c version"
    logger.debug(f"Invoking Suricatasc with {cmd=}")
    suricatasc_process = subprocess.run(cmd, capture_output=True, shell=True)
    if suricatasc_process.returncode != 0:
        # Something went wrong
        if MAX_RETRIES > 0:
            logger.warning(f"Suricatasc process had a non zero exit code: {suricatasc_process}")
            MAX_RETRIES = MAX_RETRIES - 1
            logger.info(f"Try to restart Suricata daemon, retries left: {MAX_RETRIES}")
            # Restart daemon
            rb_start_daemon(rb_logger)
        else:
            logger.error(f"Suricatasc process had a non zero exit code: {suricatasc_process}")
            raise Exception(suricatasc_process)
    logger.info(f"Suricata daemon test successful: {suricatasc_process}")
    # Reset retries
    MAX_RETRIES = 5


def rb_analyze(rb_logger, rb_pcap_pipe_path, rb_result_pipe_path, meta_json):
    """
    Analyze the network flow with rules from Suricata
    
    @param rb_logger: logger for logging
    @param rb_pcap_pipe_path: path to the pipe with the .pcap content
    @param rb_result_pipe_path: path to the pipe for the result content
    @param meta_json: path to the meta.json
    @return: nothing
    """
    # Set up logger
    global logger 
    if not logger:
        if rb_logger:
            logger = rb_logger
        else:
            logger = setup_logger()

    logger.info(f"Start using Suricata to analyze pcap data")
    # This process is named after the program
    setproctitle.setproctitle(__file__)

    # First update global path to meta.json file if not set
    global META_JSON
    if not META_JSON:
        META_JSON = meta_json

    # Use suricata on the provided pcap content
    try:
        # Set the rule update process first so that rules are updated daily using schedule modul
        schedule.every(1).day.do(rb_update_rules)
        while True:
            # Check if the scheduled job needs to be executed
            schedule.run_pending()
            # Blocks until the writer has finished its job
            with open(rb_pcap_pipe_path, "rb") as rb_pcap_pipe:
                # First test if the socket of the daemon is working
                rb_test_daemon(rb_logger)
                # Start time
                start_time = time.time()
                # Write the data to a tempfile since suricatasc cannot process streams
                temp_pcap = None
                with tempfile.NamedTemporaryFile(delete=False) as pcap_file:
                    pcap_file.write(rb_pcap_pipe.read())
                    temp_pcap = pcap_file.name
                    logger.debug(f"Created temp file {temp_pcap}")
                logger.info("Analyzing pcap with Suricatasc")
                # Use the default log directory to save the results (eve.json)
                cmd = f"suricatasc {RB_SOCKET} -c 'pcap-file {temp_pcap} {SURICATA_YAML_DIRECTORY}'"
                logger.debug(f"Invoking Suricatasc with {cmd=}")
                suricatasc_process = subprocess.run(cmd, capture_output=True, shell=True)
                if suricatasc_process.returncode != 0:
                    # Something went wrong
                    logger.error(f"Suricatasc process had a non zero exit code: {suricatasc_process}")
                    # Unlink tempfile (delete)
                    if temp_pcap:
                        os.unlink(temp_pcap)
                        logger.debug(f"Deleted temp file {temp_pcap}")
                    raise Exception(suricatasc_process) 
                else:
                    has_finished = False
                    while not has_finished:
                        cmd = f"suricatasc {RB_SOCKET} -c pcap-current"
                        logger.debug(f"Waiting for Suricatasc with {cmd=}")
                        waiting_process = subprocess.run(cmd, capture_output=True, shell=True)
                        if waiting_process.returncode != 0:
                            # Something went wrong
                            logger.error(f"Suricatasc waiting process had a non zero exit code: {waiting_process}")
                            # Unlink tempfile (delete)
                            if temp_pcap:
                                os.unlink(temp_pcap)
                                logger.debug(f"Deleted temp file {temp_pcap}")
                            raise Exception(waiting_process) 
                        else:
                            if not temp_pcap in str(waiting_process.stdout): # if the file doesn't appear, it is processed
                                has_finished = True # Done processing the pcap file
                                break
                            else:
                                logger.debug(f"Output of waiting process: {waiting_process.stdout}")
                                continue
                    # Unlink tempfile (delete)
                    if temp_pcap:
                        os.unlink(temp_pcap)
                        logger.debug(f"Deleted temp file {temp_pcap}")
                    duration_s = time.time() - start_time
                    logger.info(f"Suricatasc done: {suricatasc_process}, took {duration_s}s")
                    # Write results
                    rb_write_results(rb_result_pipe_path, duration_s)

            logger.info(f"Suricata analysis done, waiting for next pcap...")
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not analyze the pcap with Suricata: {e}")


def rb_write_results(rb_result_pipe_path, duration):
    """
    Write the matching alert content of the eve.json to the result pipe

    @param rb_result_pipe_path: path to the pipe for the result content
    @param duration: the time the suricata engine needed for the analysis in seconds
    @return: content as a string
    """
    try: 
        with open(os.path.join(SURICATA_YAML_DIRECTORY, "eve.json"), "r") as result_file:
            filtered_results = rb_filter_results(result_file.readlines(), duration)
            with open(rb_result_pipe_path, "w") as result_pipe:
                result_pipe.write(json.dumps(filtered_results))
        # Flush afterward
        with open(os.path.join(SURICATA_YAML_DIRECTORY, "eve.json"), "w") as eve_file:
            eve_file.write("")
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not write the results: {e}")
    logger.info(f"Alerts of {SURICATA_YAML_DIRECTORY}/eve.json written to {rb_result_pipe_path}")


def rb_filter_results(eve_json, duration):
    """
    Filter all valid alerts in the eve.json file

    @param eve_json: json string with the content of the eve.json file
    @param duration: the time the Suricata engine needed for the analysis in seconds
    @return: all valid alerts as a dictionary
    """
    # Structure:
    # "detections": [{"mac": "", "suricata": [], "ml": {}}]   
    alert_dictionary = {"detections": [], "statistics": {"suricataTotalRules": rb_count_rules(), "suricataAnalysisDurationMs": duration * 1000}}
    try:
        for line in eve_json:
            entry = json.loads(line)
            if entry["event_type"] == "alert":
                logger.debug(f"{entry=}")
                # Sometimes ether is not set, skip
                if "ether" in entry:
                    suricata_alert = {
                        "type": "Alert", 
                        "description": entry["alert"]["signature"], 
                        "first_occurrence": entry["timestamp"],
                        "number_occurrences": 1, # Start with 1
                        }
                    new_alert = {
                        "mac": rb_check_mac(entry["ether"]),
                        "suricata": [suricata_alert] 
                        }
                    # Before appending, check if the new alert is already present
                    has_alert = False
                    for alert in alert_dictionary["detections"]:
                        if alert["mac"] == new_alert["mac"]:
                            # Only update occurrence
                            for entry in alert["suricata"]:
                                # There is only one entry in new alert, index 0
                                if entry["description"] == new_alert["suricata"][0]["description"]:
                                    entry["number_occurrences"] += 1
                                # Add to list for known mac
                                else:
                                    alert["suricata"].append(new_alert["suricata"][0])
                                has_alert = True
                                break
                    # Only add completely new alerts
                    if not has_alert:
                        alert_dictionary["detections"].append(new_alert)
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not filter the results: {e}")
    logger.info("Finished filtering alerts from results")
    logger.debug(f"Returning alerts: {alert_dictionary}")
    return alert_dictionary


def rb_check_mac(alert_mac_adresses):
    """
    Check if an alert is related to a known mac address from the meta.json

    @param alert_mac_adresses: all possible macs extracted from the eve.json
    @return: a valid mac address as a string
    """
    logger.debug(f"Start checking mac")
    try: 
        with open(META_JSON, "r") as meta_file:
            meta_json = json.load(meta_file)
            for meta_key in meta_json.keys():
                if meta_key.lower() in alert_mac_adresses.values():
                    logger.debug("Finished checking mac")
                    return meta_key
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not check mac: {e}")


def rb_prepare_rules():
    """
    Prepare the rules for Suricata by disabling some rules, e.g. for windows environment

    @return: bool if preparing was successful
    """
    try:
        # Not case sensitive pattern to filter important rules
        # Exclude 'microsoft' from blacklist since it can be mentioned as a source or menioned in a user agent'
        # 'sslbl' by abuse.ch deprecated, remove from whitelist
        cmd = (f"grep -viE 'et info|affected_product windows|alert pkthdr|alert icmp' " # Blacklist with -v
               f"/var/lib/suricata/rules/suricata.rules | "
               f"grep -iE 'kisshome|urlhaus|et malware|confidence high|signature_severity major' " # Whitelist
               f"> /var/lib/suricata/rules/filtered.rules && "
               f"mv /var/lib/suricata/rules/filtered.rules /var/lib/suricata/rules/suricata.rules")
        logger.debug(f"Preparing rules with {cmd=}")
        preparing_process = subprocess.run(cmd, capture_output=True, shell=True)
        if preparing_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Preparing rules had a non zero exit code: {preparing_process}")
            return False
        else:
            logger.info(f"Preparing rules done: {preparing_process}")
            return True
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not prepare rules: {e}")


def rb_count_rules():
    """
    Count all active rules used by Suricata

    @return: count as an integer
    """
    try:
        # Rules with '#' are disabled, so don't count them
        cmd = f"grep -c '^[[:space:]]*alert' /var/lib/suricata/rules/suricata.rules"
        logger.debug(f"Counting rules with {cmd=}")
        counting_process = subprocess.run(cmd, capture_output=True, shell=True)
        if counting_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Counting rules had a non zero exit code: {counting_process}")
        else:
            logger.info(f"Counting rules done: {counting_process}")
            return int(counting_process.stdout)
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not count rules: {e}")


def rb_update_rules():
    """
    Runs suricata-update to update the entire ruleset and triggers the reload of rules for the daemon 

    @return: count as an integer
    """
    try:
        # First fetch new rules
        cmd = "suricata-update --suricata-conf /config/suricata.yaml"
        logger.debug(f"Invoking Suricata rule update with {cmd=}")
        update_process = subprocess.run(cmd, capture_output=True, shell=True)
        if update_process.returncode != 0:
            # Something went wrong, but don't raise manually
            logger.warning(f"Suricata update process had a non zero exit code: {update_process}")
        else:
            # Then prepare newly fetched rules for the daemon if preparation was successful
            if rb_prepare_rules():
                # Lastly, reload rules for the daemon process
                cmd = f"suricatasc {RB_SOCKET} -c reload-rules"
                logger.debug(f"Invoking Suricatasc rule reload with {cmd=}")
                suricatasc_process = subprocess.run(cmd, capture_output=True, shell=True)
                if suricatasc_process.returncode != 0:
                    # Something went wrong, but don't raise manually
                    logger.warning(f"Suricatasc rule reload process had a non zero exit code: {suricatasc_process}")
                else:
                    logger.info(f"Suricata rules updated: {update_process} and {suricatasc_process}")
            else:
                logger.warning("Suricata rule preparation failed")
    except Exception as e:
        set_state(ERROR)
        logger.exception(f"Could not update Suricata rules: {e}")


#if __name__ == '__main__':
    #rb_analyze()