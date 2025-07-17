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

from states import set_state, EXITED

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
fh = logging.FileHandler("/app/rb_analysis.log")
sh = logging.StreamHandler()
fh.setLevel(logging.DEBUG)  # set the log level for the log file
fh.setFormatter(formatter)
sh.setFormatter(formatter)
sh.setLevel(logging.INFO)  # set the log level for the console
default_logger = logging.getLogger(__name__)
default_logger.addHandler(fh)
default_logger.addHandler(sh)
default_logger.setLevel(logging.DEBUG)
default_logger.propagate = False


# Socket created by the suricata deamon
RB_SOCKET = ""


def rb_start_deamon(logger=default_logger):
    """
    Start suricata by using its deamon feature
    
    @param logger: logger for logging, default_logger
    @return: nothing
    """
    try:
        cmd = f"suricata -c /app/suricata.yaml --unix-socket -D"
        logger.debug(f"Invoking Suricata deamon with {cmd=}")
        suricatad_process = subprocess.run(cmd, capture_output=True, shell=True)
        if suricatad_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Suricata deamon process had a non zero exit code: {suricatad_process}")
            raise Exception(suricatad_process) 
        else:
            is_ready = False
            while not is_ready:
                with open(os.path.join("/app", "suricata.log"), "r") as log_file:
                    for log_line in log_file.readlines():
                        global RB_SOCKET
                        if "unix socket" in log_line and not RB_SOCKET:
                            RB_SOCKET = str(log_line).split("'")[1] # Parse socket name from line
                            logger.debug(f"Socket created at: {RB_SOCKET}")
                        if "Engine started" in log_line:
                            is_ready = True # Deamon has created socket and started engine
                            break
            logger.info(f"Suricata deamon started: {suricatad_process}")
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
        while True:
            # Blocks until the writer has finished its job
            with open(rb_pcap_pipe_path, "rb") as rb_pcap_pipe:
                # Write the data to a tempfile
                temp_pcap = None
                # Delete manually
                with tempfile.NamedTemporaryFile(delete=False) as pcap_file:
                    pcap_file.write(rb_pcap_pipe.read())
                    temp_pcap = pcap_file.name
                    logger.debug(f"Created temp file {temp_pcap}")
                logger.info("Analyzing pcap with Suricata")
                cmd = f"suricatasc {RB_SOCKET}"
                input = f"pcap-file {temp_pcap} /app\nquit\n"
                logger.debug(f"Invoking Suricata with {cmd=} and with {input=} and quit after")
                start_time = time.time()
                suricata_process = subprocess.run(cmd, input=input, text=True, capture_output=True, shell=True)
                if suricata_process.returncode != 0:
                    # Something went wrong
                    logger.warning(f"Suricata process had a non zero exit code: {suricata_process}") # TODO: Do we want to raise manually?
                    raise Exception(suricata_process) 
                else:
                    has_finished = False
                    while not has_finished:
                        cmd = f"suricatasc {RB_SOCKET}"
                        input = f"pcap-file-number\nquit\n"
                        logger.debug(f"Invoking waiting Suricata with {cmd=} and with {input=} and quit after")
                        waiting_process = subprocess.run(cmd, input=input, text=True, capture_output=True, shell=True)
                        if waiting_process.returncode != 0:
                            # Something went wrong
                            logger.warning(f"Suricata waiting process had a non zero exit code: {suricata_process}") # TODO: Do we want to raise manually?
                            raise Exception(suricata_process) 
                        else:
                            if "Success:\n0" in waiting_process.stdout:
                                has_finished = True # Done processing the pcap file
                                break
                    duration_s = time.time() - start_time
                    logger.info(f"Suricata done: {suricata_process}, took {duration_s}s")
                    # Unlink tempfile (delete)
                    if temp_pcap:
                        os.unlink(temp_pcap)
                        logger.debug(f"Deleted temp file {temp_pcap}")
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
    logger.info(f"Write alerts of /app/eve.json to {rb_result_pipe_path}")
    try: 
        with open(os.path.join("/app", "eve.json"), "r") as result_file:
            filtered_results = rb_filter_results(result_file.readlines(), duration)
            with open(rb_result_pipe_path, "w") as result_pipe:
                result_pipe.write(json.dumps(filtered_results))
        # Flush afterward
        with open(os.path.join("/app", "eve.json"), "w") as result_file:
            result_file.write("")
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not write the results: {e}")
    logger.info(f"Alerts of /app/eve.json written to {rb_result_pipe_path}")


def rb_filter_results(eve_json, duration, logger=default_logger):
    """
    Filter all valid alerts in the eve.json file

    @param eve_json: json string with the content of the eve.json file
    @param duration: the time the suricata engine needed for the analysis in seconds
    @param logger: logger for logging, default default_logger
    @return: all valid alerts as a json string
    """
    logger.info("Start filtering alerts from results")
    alert_dictionary = {"detections": [], "statistics": {"suricataTotalRules": rb_count_rules(), "suricataAalysisDurationMs": duration * 1000}}
    try:
        for line in eve_json:
            entry = json.loads(line)
            if entry["event_type"] == "alert":
                logger.debug(f"{entry=}")
                # Sometimes ether is not set, skip
                if "ether" in entry:
                    new_alert = {
                        "source": "Suricata",
                        "mac": rb_check_mac(entry["ether"]),
                        "type": "Alert", 
                        "description": entry["alert"]["signature"], 
                        "first_occurrence": entry["timestamp"],
                        "number_occurrences": 1 # Start with 1
                        }
                    # Before appending, check if the new alert is already present to update occurences
                    has_alert = False
                    for alert in alert_dictionary["detections"]:
                        if alert["mac"] == new_alert["mac"] and alert["description"] == new_alert["description"]:
                            alert["number_occurrences"] += 1
                            has_alert = True
                            break
                    # Only add new alerts
                    if not has_alert:
                        alert_dictionary["detections"].append(new_alert)
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not filter the results: {e}")
    logger.info("Finished filtering alerts from results")
    return alert_dictionary


def rb_check_mac(mac_adresses, logger=default_logger):
    """
    Check if an alert is related to a known mac address from /app/meta.json

    @param mac_adresses: all possible macs extracted from /app/eve.json
    @return: a valid mac address as a string
    """
    logger.info(f"Start checking mac")
    try: 
        with open(os.path.join("/app", "meta.json"), "r") as meta_file:
            meta_json = json.load(meta_file)
            # TODO: Add examples
            for meta_key in meta_json.keys():
                if meta_key.lower() in mac_adresses.values():
                    logger.info("Finished checking mac")
                    return meta_key.lower()
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"Could not check mac: {e}")


def rb_prepare_rules(logger=default_logger):
    """
    Prepare the rules for suricata by disabling some rules, e.g. for windows environment

    @param logger: logger for logging, default default_logger
    @return: nothing
    """
    try:
        # Not case sensitive pattern to filter important rules
        # Exclude 'microsoft' since it can be mentioned as a source or menioned in a user agent'
        cmd = (f"grep -viE 'et info|affected_product windows' " # Blacklist with -v
               f"/var/lib/suricata/rules/suricata.rules | "
               f"grep -iE 'kisshome|sslbl|et malware|confidence high|signature_severity major' " # Whitelist
               f"> /var/lib/suricata/rules/filtered.rules && "
               f"mv /var/lib/suricata/rules/filtered.rules /var/lib/suricata/rules/suricata.rules")
        logger.debug(f"Preparing rules with {cmd=}")
        preparing_process = subprocess.run(cmd, capture_output=True, shell=True)
        if preparing_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Preparing rules had a non zero exit code: {preparing_process}")
        else:
            logger.info(f"Preparing rules done: {preparing_process}")
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


#if __name__ == '__main__':
    #rb_analyze()