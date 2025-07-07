#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to aggregate the data and send it back to the adapter
"""

import logging
import requests

from states import get_state, set_state, ANALYZING, RUNNING, EXITED
from datetime import datetime
from zoneinfo import ZoneInfo
from ast import literal_eval

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
fh = logging.FileHandler("/app/aggregator.log")
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
        set_state(EXITED)
        raise
    logger.debug(f"Send {results=} to {callback_url=}")


def parse_pipes(rb_pipe_dict, ml_pipe_dict, logger=default_logger):
    """
    Parse the pipe data and create a new json object
    
    @param rb_pipe_json: pipe with the rb result content as a dict
    @param ml_pipe_json: pipe with the ml result content as a dict
    @param logger: logger for logging, default default_logger
    @return: analysis results as a dict
    """
    # Parse incoming data from pipes to a new dict to collect all gathered informations
    analysis_results = {"statistics": {}, "detections": []}

    analysis_results["detections"] = rb_pipe_dict["detections"]
    analysis_results["statistics"] = ml_pipe_dict["statistics"]
    analysis_results["statistics"]["suricata_total_rules"] = rb_pipe_dict["total_rules"]

    logger.debug(f"Finished parsing pipes to dict: {analysis_results}")
    
    return analysis_results

def aggregate(rb_result_pipe, ml_result_pipe, callback_url, pcap_name, logger=default_logger):
    """
    Aggregate the data of the rule based and ML based analysis to a result as a json
    
    @param rb_result_pipe: path to the pipe for the rb result content
    @param ml_result_pipe: path to the pipe for the ml result content
    @param callback_url: URL of the adapter to  recieve the results
    @param pcap_name: the name of the pcap file to process
    @param logger: logger for logging, default default_logger
    @return: nothing
    """
    logger.info("Start aggregation")
    while True:
        # Blocks until both writer have finished their jobs
        with open(rb_result_pipe, "r") as rb_pipe, open(ml_result_pipe, "r") as ml_pipe:
            # TODO Update data var structure
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
            # Merge to a final result as json
            try:
                info = {"file": pcap_name, 
                        "time": datetime.now(ZoneInfo("Europe/Berlin")).strftime("%d.%m.%Y %H:%M:%S %Z%z"), 
                        "result": {"status": "success"}
                        }
                data = parse_pipes(dict(literal_eval(rb_pipe.read().strip())), dict(literal_eval(ml_pipe.read().strip())))
                results = {**info, **data}
                send_results(results, callback_url)
            except Exception as e:
                logger.exception(e)
                set_state(EXITED)
            if get_state() == ANALYZING:
                # Set new state since analysis is done
                set_state(RUNNING)
