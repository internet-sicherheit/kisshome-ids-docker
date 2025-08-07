#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to analyze the .pcap files with suricata
"""

import os
import logging
import json
import subprocess
import time
import tempfile
import schedule

from logging.handlers import TimedRotatingFileHandler
from states import set_state, EXITED

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
# Rotate files each day to max 7 files, oldest will be deleted
fh = TimedRotatingFileHandler(filename="/shared/rb_analysis.log", when='D', interval=1, backupCount=7, encoding='utf-8', delay=False)
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


# Use the default log directory provided by the .yaml file
SURICATA_YAML_DIRECTORY = "/var/log/suricata"
# Socket created by the suricata deamon
RB_SOCKET = ""


def rb_start_deamon(logger=default_logger):
    """
    Start suricata by using its deamon feature
    
    @param logger: logger for logging, default_logger
    @return: nothing
    """
    try:
        # Prepare rules for the initial startup
        if rb_prepare_rules():
            # Only start when there is no suricata process running by checking for a .pid file
            if not os.path.exists("/var/run/suricata.pid"):
                cmd = f"suricata -c /config/suricata.yaml --unix-socket -D"
                logger.debug(f"Invoking Suricata deamon with {cmd=}")
                suricatad_process = subprocess.run(cmd, capture_output=True, shell=True)
                if suricatad_process.returncode != 0:
                    # Something went wrong
                    logger.warning(f"Suricata deamon process had a non zero exit code: {suricatad_process}")
                    raise Exception(suricatad_process) 
                else:
                    is_ready = False
                    while not is_ready:
                        # Use the file provided in the .yaml
                        with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "r") as log_file:
                            for log_line in log_file.readlines():
                                global RB_SOCKET
                                if "unix socket" in log_line and not RB_SOCKET:
                                    RB_SOCKET = str(log_line).split("'")[1] # Parse socket name from line
                                    logger.debug(f"Socket created at: {RB_SOCKET}")
                                if "Engine started" in log_line:
                                    is_ready = True # Deamon has created socket and started engine
                                    break
                    logger.info(f"Suricata deamon started: {suricatad_process}")
            else:
                logger.warning("Suricata already running")
        else:
            logger.warning("Suricata rule preparation failed")
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not start Suricata deamon: {e}")

def rb_analyze(rb_pcap_pipe_path, rb_result_pipe_path, logger=default_logger):
    """
    Analyze the network flow with rules from suricata
    
    @param rb_pcap_pipe_path: path to the pipe with the .pcap content
    @param rb_result_pipe_path: path to the pipe for the result content
    @param logger: logger for logging, default_logger
    @return: nothing
    """
    logger.info(f"Start using suricata to analyze pcap data")
    # Use suricata on the provided pcap content
    try:
        # Set the rule update process first so that rules are updated daily using schedule modul
        schedule.every(1).day.do(rb_update_rules)
        while True:
            # Check if the scheduled job needs to be executed
            schedule.run_pending()
            # Blocks until the writer has finished its job
            with open(rb_pcap_pipe_path, "rb") as rb_pcap_pipe:
                start_time = time.time()
                # Write the data to a tempfile since suricatasc cannot process streams
                temp_pcap = None
                # Delete manually
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
                    logger.warning(f"Suricatasc process had a non zero exit code: {suricatasc_process}") # TODO: Do we want to raise manually?
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
                            logger.warning(f"Suricatasc waiting process had a non zero exit code: {waiting_process}") # TODO: Do we want to raise manually?
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
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not analyze the pcap with Suricata: {e}")


def rb_write_results(rb_result_pipe_path, duration, logger=default_logger):
    """
    Write the matching alert content of the eve.json to the result pipe

    @param rb_result_pipe_path: path to the pipe for the result content
    @param duration: the time the suricata engine needed for the analysis in seconds
    @param logger: logger for logging, default_logger
    @return: content as a string
    """
    logger.info(f"Write alerts of {SURICATA_YAML_DIRECTORY}/eve.json to {rb_result_pipe_path}")
    try: 
        with open(os.path.join(SURICATA_YAML_DIRECTORY, "eve.json"), "r") as result_file:
            filtered_results = rb_filter_results(result_file.readlines(), duration)
            with open(rb_result_pipe_path, "w") as result_pipe:
                result_pipe.write(json.dumps(filtered_results))
        # Flush afterward
        with open(os.path.join(SURICATA_YAML_DIRECTORY, "eve.json"), "w") as eve_file:
            eve_file.write("")
        with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "w") as log_file:
            log_file.write("")
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not write the results: {e}")
    logger.info(f"Alerts of {SURICATA_YAML_DIRECTORY}/eve.json written to {rb_result_pipe_path}")


def rb_filter_results(eve_json, duration, logger=default_logger):
    """
    Filter all valid alerts in the eve.json file

    @param eve_json: json string with the content of the eve.json file
    @param duration: the time the suricata engine needed for the analysis in seconds
    @param logger: logger for logging, default default_logger
    @return: all valid alerts as a dictionary
    """
    logger.info("Start filtering alerts from results")
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
                            # Only update occurence
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
        set_state(EXITED)
        logger.exception(f"Could not filter the results: {e}")
    logger.info("Finished filtering alerts from results")
    logger.debug(f"Returning alerts: {alert_dictionary}")
    return alert_dictionary


def rb_check_mac(alert_mac_adresses, logger=default_logger):
    """
    Check if an alert is related to a known mac address from the meta.json

    @param alert_mac_adresses: all possible macs extracted from the eve.json
    @return: a valid mac address as a string
    """
    logger.debug(f"Start checking mac")
    try: 
        with open(os.path.join("/config", "meta.json"), "r") as meta_file:
            meta_json = json.load(meta_file)
            # TODO: Add examples
            for meta_key in meta_json.keys():
                if meta_key.lower() in alert_mac_adresses.values():
                    logger.debug("Finished checking mac")
                    return meta_key.lower()
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not check mac: {e}")


def rb_prepare_rules(logger=default_logger):
    """
    Prepare the rules for suricata by disabling some rules, e.g. for windows environment

    @param logger: logger for logging, default default_logger
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
        set_state(EXITED)
        logger.exception(f"Could not prepare rules: {e}")


def rb_count_rules(logger=default_logger):
    """
    Count all active rules used by suricata

    @param logger: logger for logging, default default_logger
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
        set_state(EXITED)
        logger.exception(f"Could not count rules: {e}")


def rb_update_rules(logger=default_logger):
    """
    Runs suricata-update to update the entire ruleset and triggers the reload of rules for the deamon 

    @param logger: logger for logging, default default_logger
    @return: count as an integer
    """
    try:
        # First fetch new rules
        cmd = "suricata-update"
        logger.debug(f"Invoking Suricata rule update with {cmd=}")
        update_process = subprocess.run(cmd, capture_output=True, shell=True)
        if update_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Suricata update process had a non zero exit code: {update_process}")
            raise Exception(update_process) 
        else:
            # Then prepare newly fetched rules for the deamon if preparation was successful
            if rb_prepare_rules():
                # Lastly, reload rules for the deamon process
                cmd = f"suricatasc {RB_SOCKET} -c reload-rules"
                logger.debug(f"Invoking Suricatasc rule reload with {cmd=}")
                suricatasc_process = subprocess.run(cmd, capture_output=True, shell=True)
                if suricatasc_process.returncode != 0:
                    # Something went wrong
                    logger.warning(f"Suricatasc rule reload process had a non zero exit code: {suricatasc_process}")
                    raise Exception(suricatasc_process) 
                else:
                    logger.info(f"Suricata rules updated: {update_process} and {suricatasc_process}")
            else:
                logger.warning("Suricata rule preparation failed")
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not update Suricata rules: {e}")


#if __name__ == '__main__':
    #rb_analyze()