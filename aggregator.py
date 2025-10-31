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
Script to aggregate the data and send it back to the adapter
"""

import logging
import requests
import os
import glob
import setproctitle
import json
import time

from logging.handlers import TimedRotatingFileHandler
from states import get_state, set_state, ANALYZING, RUNNING, ERROR
from monitor import get_cpuinfo, get_gpuinfo, start_monitoring, stop_monitoring, SYSSTAT_DIRECTORY
from datetime import datetime, timezone
from ast import literal_eval

LOG_DIR = "/shared/logs"
LOG_NAME = "aggregator.log"

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


# The meta.json file path
META_JSON = os.path.join("/config", "meta.json")
# Use the default log directory provided by the .yaml file
SURICATA_YAML_DIRECTORY = "/var/log/suricata"
# Directory to save the monitor data
SYSSTAT_DIRECTORY = "/stat"
    

logger = None


def load_json_from_file(monitoring_file_name):
    """
    Load file content and parse to json format

    @param monitoring_file_name: name of monitoring file to be parsed
    @return: dict with the parsed file content, else raw content
    """
    result = {monitoring_file_name: {}}
    monitoring_file = f"{monitoring_file_name}.json"
    try:
        with open(os.path.join(SYSSTAT_DIRECTORY, monitoring_file), "r") as stat_file:
            result[monitoring_file_name] = json.load(stat_file)
    except json.JSONDecodeError:
        # Retry with fix caused by an unfinished INTERRUPT
        with open(os.path.join(SYSSTAT_DIRECTORY, monitoring_file), "r") as stat_file:
            lines = stat_file.readlines()
        try:
            lines.append("]}]}}")
            result[monitoring_file_name] = json.loads("".join(lines))
        except json.JSONDecodeError:
            # Last resort: return raw lines
            result[monitoring_file_name] = lines
    logger.debug(f"{result=}")
    logger.info(f"Loaded json from file {monitoring_file_name}.json")
    return result


def collect_suricata_telemetry():
    """
    Collect suricata telemetry about the environment
    
    @return: dict with suricata telemetry
    """
    # Create dictionary to return
    suricata_telemetry = {}

    # Collect telemetry
    suricata_log = {"suricata_log": []}
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "r") as log_file:
        suricata_log["suricata_log"] = log_file.readlines()
    suricata_stat = {"suricata_stat": []}
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "stats.log"), "r") as stat_file:
        suricata_stat["suricata_stat"] = stat_file.readlines()

    # Flush afterward
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "w") as log_file:
        log_file.write("")
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "stats.log"), "w") as stat_file:
        stat_file.write("")

    # Return results
    suricata_telemetry = {**suricata_log, **suricata_stat}
    logger.debug(f"{suricata_telemetry=}")
    logger.info(f"Finished collection of suricata telemetry")
    return suricata_telemetry


def collect_hardware():
    """
    Collect hardware informations about the environment
    
    @return: dict with hardware informations
    """
    # Create dictionary to return
    hardware = {}

    # Collect hardware informations
    cpu = {"cpu": [str(get_cpuinfo()).strip()]}
    gpu = {"gpu": [str(get_gpuinfo()).strip()]}

    # Return results
    hardware = {**cpu, **gpu}
    logger.debug(f"{hardware=}")
    logger.info(f"Finished collection of hardware informations")
    return hardware


def collect_monitor_data():
    """
    Collect monitored data about the environment
    
    @return: dict with monitored data
    """
    # Create dictionary to return
    monitor_data = {}

    # Collect monitor data
    iostat = load_json_from_file("iostat")
    pidstat = load_json_from_file("pidstat")
    sar = load_json_from_file("sar")
    
    # Flush afterward
    with open(os.path.join(SYSSTAT_DIRECTORY, "iostat.json"), "w") as iostat_file:
        iostat_file.write("")
    with open(os.path.join(SYSSTAT_DIRECTORY, "pidstat.json"), "w") as pidstat_file:
        pidstat_file.write("")
    with open(os.path.join(SYSSTAT_DIRECTORY, "sar.json"), "w") as sar_file:
        sar_file.write("")

    # Return results
    monitor_data = {**iostat, **pidstat, **sar}
    logger.debug(f"{monitor_data=}")
    logger.info(f"Finished collection of monitor data")
    return monitor_data


def send_results(results, callback_url):
    """
    Send results to a given URL
    
    @param results: the results as a json
    @param callback_url: URL of the adapter to  recieve the results
    @return: nothing
    """
    # TODO Send results to the provided url
    try:
        #http://172.17.0.1:4711/data -> docker0 bridge on the host
        logger.debug(f"Sending {results=} to {callback_url=}")
        logger.info(f"Sending results to {callback_url=}")

        resp = requests.post(callback_url, json=results, verify=False)
        resp.raise_for_status()
    except Exception as e:
        logger.exception(e)
        set_state(ERROR)
        raise
    logger.info(f"Send {results=} to {callback_url=}")


def aggregate_pipes(rb_pipe_dict, ml_pipe_dict, known_macs):
    """
    Aggregate the pipe data and create a new json object
    
    @param rb_pipe_json: pipe with the rb result content as a dict
    @param ml_pipe_json: pipe with the ml result content as a dict
    @param known_macs: list with all current devices by mac addresses
    @return: analysis results as a dict
    """
    # Parse incoming data from pipes to a new dict to collect all gathered informations
    analysis_results = {"statistics": {}, "detections": []}

    # Aggregate the detections first
    for mac in known_macs:
        analysis_results["detections"].append({"mac": mac})

    # Get macs from detections as list in upper case with delimiter ':'
    rb_macs = [str(rb_mac["mac"]) for rb_mac in rb_pipe_dict["detections"]] # Format rb_pipe: AA:BB:CC:DD:EE:FF
    ml_macs = [str(ml_mac).replace('-', ':').upper() for ml_mac in ml_pipe_dict["detections"].keys()] # Format ml_pipe: aa-bb-cc-dd-ee-ff

    for detection in analysis_results["detections"]:
        current_mac = detection["mac"]
        # Suricata first
        if current_mac in rb_macs:
            detection["suricata"] = rb_pipe_dict["detections"][rb_macs.index(current_mac)]["suricata"]
            # Add score of 100 to each alert (TUHH)
            for alert in detection["suricata"]:
                alert["score"] = 100
        else:
            # Mac is missing, create entry for it
            detection["suricata"] = []

        # ML second
        if current_mac in ml_macs:
            # Random score wil be added in the adapter, report real scores
            # Cast back to aa-bb-cc-dd-ee-ff to get the value
            detection["ml"] = ml_pipe_dict["detections"][current_mac.replace(':', '-').lower()]
        else:
            new_ml_detection = {
                "type": "Normal",
                "description": "",
                "score": 0
                } 
            detection["ml"] = new_ml_detection

    # Then aggregate the statistics
    for device in ml_pipe_dict["statistics"]["devices"]:
        device["mac"] = device["mac"].replace("-", ":").upper() # Fix mac in ml statistics
    analysis_results["statistics"] = {**rb_pipe_dict["statistics"], **ml_pipe_dict["statistics"]}

    logger.debug(f"{analysis_results=}")
    logger.info(f"Finished parsing pipes to dictionary")
    
    return analysis_results


def aggregate(aggregator_logger, rb_result_pipe, ml_result_pipe, callback_url, save_threshold_seconds, allow_training, pcap_name):
    """
    Aggregate the data of the rule based and ML based analysis to a result as a json
    
    @param aggregator_logger: logger for logging
    @param rb_result_pipe: path to the pipe for the rb result content
    @param ml_result_pipe: path to the pipe for the ml result content
    @param callback_url: URL of the adapter to  recieve the results
    @param save_threshold_seconds: interval in seconds between each regular analysis attempt set by the user
    @param allow_training: boolean if the user allows training of devices
    @param pcap_name: the name of the pcap file to process
    @return: nothing
    """
    # Set up logger
    global logger 
    if not logger:
        if aggregator_logger:
            logger = aggregator_logger
        else:
            logger = setup_logger()

    logger.info("Start aggregation")

    # This process is named after the program
    setproctitle.setproctitle(__file__)

    while True:
        # Blocks until both writer have finished their jobs
        with open(rb_result_pipe, "r") as rb_pipe, open(ml_result_pipe, "r") as ml_pipe:
            # Current version
            #
            # "detections": [                                               # Liste mit Eintrag für jedes Gerät aus der Config
            # {
            # "mac": "00:07:e9:13:37:46",
            # "suricata": [                                                 # Liste mit Suricata Results
            #     {
            #     "type": "Alert",
            #     "description": "ET MALWARE DDoS.XOR Checkin via HTTP",
            #     "first_occurrence": "2024-03-06T02:45:44.595361+0000",
            #     "num_occurrences": "2"
            #     "score": "100"
            #     },
            #     {
            #     "type": "Alert",
            #     "description": "ET MALWARE DDoS.XOR Checkin",
            #     "first_occurrence": "2024-03-06T02:45:54.595361+0000",
            #     "num_occurrences": "1"
            #     "score": "100"
            #     }
            # ],
            # "ml": {                                                       # Dict mit ML Result
            #     "type": "Alert",
            #     "description": "Anomaly detected",
            #     "score": 81.52,                                           # Wenn  detection dann Durchschintt der Scores die über treshold lagen?
            # }
            # },
            # {
            # "mac": "0a:05:b6:23:94:66",
            # "suricata": [],                                               # Suricata Liste kann leer sein
            # "ml": {
            #     "type": "Normal",
            #     "description": "No Anomalies detected",
            #     "score": 5.10,                                            # Wenn keine detection dann Durchschnitt über alle Auswertungen?
            # }
            # },
            # {
            # "mac": "bc:93:81:fe:44:32",
            # "suricata": [],
            # "ml": {
            #     "type": "Normal",                                           # Inactive?
            #     "description": "",
            #     "score": 0.0,                                               # 0.0 wenn keine Pakete vorhanden
            # }
            # }
            # ]
            #
            #
            #
            # FROM ML:
            # [
            #   {<MAC1>: {
            #     "type": "Alert",   # Normal, Alert
            #     "description": "47 Anomalies detected",
            #     "score": 64.09
            #     }
            #   },
            #   {<MAC4>: {
            #     "type": "Normal",   # Normal, Alert
            #     "description": "29 Anomalies detected",
            #     "score": 43.45
            #     }
            #   }
            # ]
            #
            #
            #
            # Merge to a final result as json
            try:
                # In case the timeout is not reached, stop the monitoring
                stop_monitoring()

                # Get current macs from meta.json
                current_macs = []
                with open(META_JSON, "r") as meta_file:
                    current_macs = json.load(meta_file).keys()

                head = {"file": pcap_name, 
                        "time": datetime.now(timezone.utc).isoformat(), 
                        "result": {"status": "success"}
                        }

                pipe_data = aggregate_pipes(dict(literal_eval(rb_pipe.read().strip())), dict(literal_eval(ml_pipe.read().strip())), current_macs)
                
                config = {"config": {"callback_url": "", "save_threshold_seconds": "", "allow_training": False, "meta_json": {}}}
                config["config"]["callback_url"] = callback_url
                config["config"]["save_threshold_seconds"] = save_threshold_seconds
                config["config"]["allow_training"] = allow_training
                if os.path.exists(META_JSON):
                    with open(META_JSON, "r") as meta_file:
                        config["config"]["meta_json"] = json.load(meta_file)

                suricata_telemetry = {"suricata_telemetry": {}}
                suricata_telemetry["suricata_telemetry"] = collect_suricata_telemetry()

                hardware = {"hardware": {}}
                hardware["hardware"] = collect_hardware()
                
                monitor_data = {"monitor": {}}
                monitor_data["monitor"]["load"] = collect_monitor_data()

                # Wait a little
                time.sleep(1)

                # Start idle monitoring for max. 10 seconds
                start_monitoring(timeout=10)
                time.sleep(10)
                stop_monitoring()

                monitor_data["monitor"]["idle"] = collect_monitor_data()
                
                results = {**head, **pipe_data, **config, **suricata_telemetry, **hardware, **monitor_data}
                send_results(results, callback_url)

                if get_state() == ANALYZING:
                    # Set new state since analysis is done
                    set_state(RUNNING)

            except Exception as e:
                logger.exception(e)
                set_state(ERROR)
            
            logger.info(f"Aggregation for {pcap_name=} done, waiting for next pcap...")