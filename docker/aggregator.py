#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to aggregate the data and send it back to the adapter
"""

import logging
import requests
import os
import glob
import setproctitle
import json
import random

from logging.handlers import TimedRotatingFileHandler
from states import get_state, set_state, ANALYZING, RUNNING, ERROR
from monitor import get_cpuinfo, get_gpuinfo, stop_monitoring, SYSSTAT_DIRECTORY
from datetime import datetime
from zoneinfo import ZoneInfo
from ast import literal_eval

LOG_DIR = "/shared/logs"
LOG_NAME = "aggregator.log"

# Ensure that the log directory exist and old files are deleted
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, LOG_NAME)
for old_log in glob.glob(f"{log_path}.*"):
    os.remove(old_log)
# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
# Rotate files each day to max 7 files, oldest will be deleted
fh = TimedRotatingFileHandler(filename=log_path, when='D', interval=1, backupCount=7, encoding='utf-8', delay=False)
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


# Anomaly strings
ANOMALY = "Anomalies detected"
NO_ANOMALY = "No anomalies detected"
# The file with the training information
TRAINING_JSON = os.path.join("/shared/ml", "training_progress.json")
# The meta.json file path
META_JSON = os.path.join("/config", "meta.json")
# Use the default log directory provided by the .yaml file
SURICATA_YAML_DIRECTORY = "/var/log/suricata"
    

def collect_meta():
    """
    Collect informations about the environment
    
    @return: dict with meta informations
    """
    # Create dictionary to return
    meta_informations = {"meta": {}}

    # 1: Get suricata stats as strings in list
    
    suricata_log = {"suricata_log": []}
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "r") as log_file:
        suricata_log["suricata_log"] = log_file.readlines()
    # Flush afterward
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "suricata.log"), "w") as log_file:
        log_file.write("")

    suricata_stat = {"suricata_stat": []}
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "stats.log"), "r") as stat_file:
        suricata_stat["suricata_stat"] = stat_file.readlines()
    # Flush afterward
    with open(os.path.join(SURICATA_YAML_DIRECTORY, "stats.log"), "w") as stat_file:
        stat_file.write("")

    # 2: Get hardware stats as strings

    cpu = {"cpu": [str(get_cpuinfo()).strip()]}
    gpu = {"gpu": [str(get_gpuinfo()).strip()]}

    # 3: Get monitor data as json

    iostat = {"iostat": []}
    with open(os.path.join(SYSSTAT_DIRECTORY, "iostat.json"), "r") as iostat_file:
        try:
            iostat["iostat"] = json.load(iostat_file)
        except json.JSONDecodeError: # Sometimes it failes 
            iostat_file.seek(0)
            lines = iostat_file.readlines()
            # Add missing lines
            lines.append("]}]}}")
            iostat["iostat"] = json.loads("".join(lines))

    pidstat = {"pidstat": []}
    with open(os.path.join(SYSSTAT_DIRECTORY, "pidstat.json"), "r") as pidstat_file:
        try:
            pidstat["pidstat"] = json.load(pidstat_file)
        except json.JSONDecodeError: # Sometimes it failes 
            pidstat_file.seek(0)
            lines = pidstat_file.readlines()
            # Add missing lines
            lines.append("]}]}}")
            pidstat["pidstat"] = json.loads("".join(lines))

    sar = {"sar": {}}
    with open(os.path.join(SYSSTAT_DIRECTORY, "sar.json"), "r") as sar_file:
        sar["sar"] = json.load(sar_file)
    
    # Flush afterward
    with open(os.path.join(SYSSTAT_DIRECTORY, "iostat.json"), "w") as iostat_file:
        iostat_file.write("")
        # Flush afterward
    with open(os.path.join(SYSSTAT_DIRECTORY, "pidstat.json"), "w") as pidstat_file:
        pidstat_file.write("")
    with open(os.path.join(SYSSTAT_DIRECTORY, "sar.json"), "w") as sar_file:
        sar_file.write("")

    # Return results
    meta_informations["meta"] = {**suricata_log, **suricata_stat, **cpu, **gpu, **iostat, **pidstat, **sar}
    return meta_informations


def send_results(results, callback_url, logger=default_logger):
    """
    Send results to a given URL
    
    @param results: the results as a json
    param callback_url: URL of the adapter to  recieve the results
    @param logger: logger for logging, default default_logger
    @return: nothing
    """
    # TODO Send results to the provided url
    try:
        #http://172.17.0.1:4711/data -> docker0 bridge on the host
        logger.info(f"Sending {results=} to {callback_url=}")

        resp = requests.post(callback_url, json=results, verify=False)
        resp.raise_for_status()
    except Exception as e:
        logger.exception(e)
        set_state(ERROR)
        raise
    logger.debug(f"Send {results=} to {callback_url=}")


def aggregate_pipes(rb_pipe_dict, ml_pipe_dict, logger=default_logger):
    """
    Aggregate the pipe data and create a new json object
    
    @param rb_pipe_json: pipe with the rb result content as a dict
    @param ml_pipe_json: pipe with the ml result content as a dict
    @param logger: logger for logging, default default_logger
    @return: analysis results as a dict
    """
    # Parse incoming data from pipes to a new dict to collect all gathered informations
    analysis_results = {"statistics": {}, "detections": []}

    # Aggregate the detections first
    # Get known macs from meta.json
    known_macs = []
    with open(os.path.join("/config", "meta.json"), "r") as meta_file:
        known_macs = json.load(meta_file).keys()

    for mac in known_macs:
        analysis_results["detections"].append({"mac": mac})

    # Get keys of 
    rb_macs = [str(rb_mac["mac"]).lower() for rb_mac in rb_pipe_dict["detections"]]
    ml_macs = [str(ml_mac["mac"]).lower() for ml_mac in ml_pipe_dict["detections"]]

    for detection in analysis_results["detections"]:
        current_mac = str(detection["mac"]).lower()
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
            detection["ml"] = ml_pipe_dict["detections"][ml_macs.index(current_mac)]["ml"]
            # Add random score (TUHH) -> TODO: MOVE TO ADAPTER
            # random.random(): [0.0, 1.0)
            if "Alert" in detection["ml"]["type"]:
                detection["ml"]["score"] = round(90 + random.random() * 10, 2) # [90.0, 100.0)
            if "Normal" in detection["ml"]["type"]:
                detection["ml"]["score"] = round(random.random() * 10, 2) # [0.0, 10.0)
        else:
            new_ml_detection = {
                "type": "Normal",
                "description": "",
                "first_occurrence": "",
                "number_occurrences": 0,
                "score": 0
                } 
            detection["ml"] = new_ml_detection

    # Then aggregate the statistics
    analysis_results["statistics"] = {**rb_pipe_dict["statistics"], **ml_pipe_dict["statistics"]}

    logger.debug(f"Finished parsing pipes to dict: {analysis_results}")
    
    return analysis_results


def aggregate(rb_result_pipe, ml_result_pipe, callback_url, allow_training, pcap_name, logger=default_logger):
    """
    Aggregate the data of the rule based and ML based analysis to a result as a json
    
    @param rb_result_pipe: path to the pipe for the rb result content
    @param ml_result_pipe: path to the pipe for the ml result content
    @param callback_url: URL of the adapter to  recieve the results
    @param allow_training: boolean if the user allows training of devices
    @param pcap_name: the name of the pcap file to process
    @param logger: logger for logging, default default_logger
    @return: nothing
    """
    logger.info("Start aggregation")

    # This process is named after the program
    setproctitle.setproctitle(__file__)

    while True:
        # Blocks until both writer have finished their jobs
        with open(rb_result_pipe, "r") as rb_pipe, open(ml_result_pipe, "r") as ml_pipe:
            # TODO: Update data var structure
            #
            # TODO: First version (Lastenheft)
            #
            # Example:
            # {
            #     "file": "2020-09-23T14:00:00.pcap",
            #     "result": {
            #         "status": "success",
            #         "error": "Optional error text"
            #     },
            #     "statistics": {
            #         "analysisDurationMs": 10000,
            #         "totalBytes": 15900,
            #         "packets": 105,
            #         "devices": [
            #             {
            #                 "mac": "00:00:00:00:00:00",
            #                 "countries": [
            #                     {
            #                         "country": "US",
            #                         "bytes": 10000
            #                     },
            #                     {
            #                         "country": "CA",
            #                         "bytes": 5900
            #                     }
            #                 ],
            #                 "bytes": 15900
            #             }
            #         ]
            #     },
            #     "detections": [
            #         {
            #             "mac": "00:00:00:00:00:00",
            #             "type": "Warning/Alert",
            #             "description": "Full description of event",
            #             "time": "2025-03-25T14:00:00.000Z"
            #         }
            #     ]
            # }
            #
            #
            #
            # TODO: Second version (Gerhard, 17-07-2025)
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
            # "ML": {                                                       # Dict mit ML Result
            #     "type": "Warning",
            #     "description": "Anomaly detected",
            #     "first_occurrence": "TODO",                                 # Erstes packet, Beginn erstes window, Beginn erster flow... mit detection
            #     "num_occurrences": "100",                                   # Anzahl results über threshold
            #     "score": 81.52,                                # Wenn  detection dann Durchschintt der Scores die über treshold lagen?
            # }
            # },
            # {
            # "mac": "0a:05:b6:23:94:66",
            # "suricata": [],                                               # Suricata Liste kann leer sein
            # "ML": {
            #     "type": "Normal",
            #     "description": "No Anomalies detected", or None
            #     "first_occurrence": None,                                 # Erstes packet, Beginn erstes window, Beginn erster flow... der PCAP
            #     "num_occurrences": "0",                                     # 0 oder Anzahl überprüfter Pakete, Windows, Flows...?
            #     "score": 5.10,                                # Wenn keine detection dann Durchschnitt über alle Auswertungen?
            # }
            # },
            # {
            # "mac": "bc:93:81:fe:44:32",
            # "suricata": [],
            # "ML": {
            #     "type": "Inactive",
            #     "description": "No Packets",
            #     "first_occurrence": "TODO",                                 # ? Eigentlich, egal vieleicht 1. Januar 1970 00:00:00
            #     "num_occurrences": "0",                                     # 0
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
            #     "type": "Warning",   # Normal, Alert
            #     "description": "47 Anomalies detected",
            #     "first_occurrence": "some data",
            #     "num_occurrences": 47,
            #     }
            #   },
            #   {<MAC4>: {
            #     "type": "Warning",   # Normal, Alert
            #     "description": "29 Anomalies detected",
            #     "first_occurrence": "some date",
            #     "num_occurrences": 29,
            #     }
            #   }
            # ]
            #
            #
            #
            # Merge to a final result as json

            # In case the timeout is not reached, stop the monitoring
            stop_monitoring()

            try:
                info = {"file": pcap_name, 
                        "time": datetime.now(ZoneInfo("Europe/Berlin")).isoformat(), 
                        "result": {"status": "success"}
                        }
                
                data = aggregate_pipes(dict(literal_eval(rb_pipe.read().strip())), dict(literal_eval(ml_pipe.read().strip())))
                
                # Load training_progress.json
                training = {"training": {}}
                if os.path.exists(TRAINING_JSON):
                    with open(TRAINING_JSON, "r") as training_file:
                        training["training"] = json.load(training_file)
                
                config = {"config": {"allow_training": False, "callback_url": "", "meta_json": {}}}
                config["config"]["allow_training"] = allow_training
                config["config"]["callback_url"] = callback_url
                if os.path.exists(META_JSON):
                    with open(META_JSON, "r") as meta_file:
                        config["config"]["meta_json"] = json.load(meta_file)

                meta = collect_meta()
                
                results = {**info, **data, **training, **config, **meta}
                send_results(results, callback_url)

                if get_state() == ANALYZING:
                    # Set new state since analysis is done
                    set_state(RUNNING)

            except Exception as e:
                logger.exception(e)
                set_state(ERROR)