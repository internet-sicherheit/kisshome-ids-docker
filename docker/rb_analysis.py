#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to analyze the .pcap files with suricata
"""

import os
import logging
import json
import subprocess

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
            cmd = f"suricata -c /etc/suricata/suricata.yaml -vvv -l /app -r {rb_pcap_pipe_path} --pcap-file-continuous"
            logger.debug(f"Invoking suricata with {cmd=}")
            suricata_process = subprocess.run(cmd, capture_output=True, shell=True)
            if suricata_process.returncode != 0:
                # Something went wrong
                logger.warning(f"Suricata process had a non zero exit code: {suricata_process}")
            else:
                logger.info(f"Suricata done: {suricata_process}")
                # Write results
                rb_write_results(rb_result_pipe_path=rb_result_pipe_path)
    except Exception as e:
        logger.error(f"Could not analyze the pcap with suricata: {e}")


def rb_write_results(rb_result_pipe_path, logger=default_logger):
    """
    Write the matching alert content of the eve.json to the result pipe

    @param rb_result_pipe_path: path to the pipe for the result content
    @param logger: logger for logging, default_logger
    @return: content as a string
    """
    logger.info(f"Write content of /app/eve.json to {rb_result_pipe_path}")
    with open(os.path.join("/app", "eve.json"), "r") as result_file:
        with open(rb_result_pipe_path, "w") as result_pipe:
            filtered_results = rb_filtered_results(result_file.readlines())
            json.dump(filtered_results, result_pipe)
    # Flush afterward
    with open(os.path.join("/app", "eve.json"), "w") as result_file:
        result_file.write("")
    logger.info(f"Content of /app/eve.json written to {rb_result_pipe_path}")


def rb_filtered_results(eve_json, logger=default_logger):
    """
    Filter all valid alerts in the eve.json file

    @param eve_json: json string with the content of the eve.json file
    @param logger: logger for logging, default default_logger
    @return: all valid alerts as a json string
    """
    logger.info("Start filtering alerts from results")
    alert_dictionary = {"total_rules": rb_count_rules(), "detections": []}
    for line in eve_json:
        entry = json.loads(line)
        if entry["event_type"] == "alert":
            logger.debug(f"{entry=}")
            # Sometimes ether is not set
            if "ether" in entry:
                valid_alert = {
                    "mac": entry["ether"], # TODO: Is mac inboud/outbound?
                    "type": "Alert", 
                    "description": entry["alert"]["signature"], 
                    "time": entry["timestamp"]
                    }
                alert_dictionary["detections"].append(valid_alert)
    logger.info("Finished filtering alerts from results")
    return alert_dictionary


def rb_prepare_rules(logger=default_logger):
    """
    Prepare the rules for suricata by disabling some rules, e.g. for windows environment

    @param logger: logger for logging, default default_logger
    @return: nothing
    """
    try:
        # Not case sensitive pattern to filter IoT related rules
        # Include 'microsoft' or 'windows' since it can be mentioned as a source or menioned in a user agent'
        cmd = (f"grep -viE 'et info' " # Blacklist with -v
               f"/var/lib/suricata/rules/suricata.rules | "
               f"grep -iE 'sslbl|et malware|confidence high|signature_severity major' " # Whitelist
               f"> /var/lib/suricata/rules/filtered.rules && "
               f"mv /var/lib/suricata/rules/filtered.rules /var/lib/suricata/rules/suricata.rules") # TODO: Whitelisting vs. Blacklisting? Or both?
        logger.debug(f"Preparing rules with {cmd=}")
        preparing_process = subprocess.run(cmd, capture_output=True, shell=True)
        if preparing_process.returncode != 0:
            # Something went wrong
            logger.warning(f"Preparing rules had a non zero exit code: {preparing_process}")
        else:
            logger.info(f"Preparing rules done: {preparing_process}")
    except Exception as e:
        logger.error(f"Could not prepare rules: {e}")


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
        logger.error(f"Could not count rules: {e}")


#if __name__ == '__main__':
    #rb_analyze()