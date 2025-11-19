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
Script to start the API 
"""

import os
import glob
import setproctitle
import logging
import json
import gzip
import base64
import time
import psutil

from logging.handlers import TimedRotatingFileHandler
from flask import Flask, request
from flask_restx import Api, Resource, fields, reqparse, inputs
from werkzeug.datastructures import FileStorage
from threading import Lock
from filelock import FileLock
from kisshome_ids import KisshomeIDS
from states import *
from monitor import start_monitoring

LOG_DIR = "/shared/logs"
LOG_NAME = "flask_api.log"

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
logger = logging.getLogger(__name__)
logger.addHandler(fh)
logger.addHandler(sh)
logger.setLevel(logging.INFO)
logger.propagate = False


# This process is named after the program
setproctitle.setproctitle(__file__)

# Version
VERSION = "1.6.6"

# For pcap check
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # Big-endian, microsecond resolution (standard)
    b"\xd4\xc3\xb2\xa1",  # Little-endian, microsecond resolution (standard)
    b"\xa1\xb2\x3c\x4d",  # Big-endian, nanosecond resolution (standard)
    b"\x4d\x3c\xb2\xa1",  # Little-endian, nanosecond resolution (standard)
    b"\xa1\xb2\xcd\x34",  # Big-endian, microsecond resolution (Fritz!Box / rare embedded variant)
    b"\x34\xcd\xb2\xa1"   # Little-endian, microsecond resolution (Fritz!Box / rare embedded variant)
}

# For pcapng check
PCAPNG_MAGIC_NUMBER = b'\x0a\x0d\x0d\x0a'  # Bi-endian, pcapng (standard)

# Initialize Locks
pipe_lock = Lock()
meta_lock = FileLock(f"/config/meta.json.lock")

# Remember if logs were send
logs_send = False

# Initialize app and make it RESTful
app = Flask(__name__)


def configure_app(flask_app):
    """
    """
    flask_app.config['SWAGGER_UI_DOC_EXPANSION'] = True
    flask_app.config['RESTX_VALIDATE'] = True
    flask_app.config['RESTX_MASK_SWAGGER'] = False
    flask_app.config['ERROR_404_HELP'] = True  # False in prod
    logger.info(f"Start Flask API with version {VERSION}")


def yield_active_processes():
    """
    """
    # Get all processes whose name matches the script set via setproctitle
    target_processes = []

    for proc in psutil.process_iter():
        try:
            if "/app/" in proc.name():
                target_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Log results
    if target_processes:
        logger.info("Active python processes:")
        for proc in target_processes:
            pid = proc.pid
            # cmdline is a list
            for arg in proc.cmdline():
                if arg and ".py" in arg.strip():
                    name = arg.strip()
            is_alive = proc.is_running()
            logger.info(f"Process with {name=} has {pid=}, {is_alive=}")


# Configure API
configure_app(app)


ids = KisshomeIDS()


api = Api(app, version=VERSION, title=f'{ENV_NAME} API',
          description=f'A RESTful API to interact with the {ENV_NAME}')

ns = api.namespace("", description=f"{ENV_NAME} operations")

# Models for JSON like requests or responses
status_configuration_model = ns.model("Status configuration",
    {
        "callback_url": fields.String(required=True, description="The current callback URL for the IDS"),
        "save_threshold_seconds": fields.String(required=True, description="The current interval in seconds set for regular analysis attempts for the IDS"),
        "allow_training": fields.Boolean(required=True, description="The current value for allowing training for the IDS"),
        "meta_json": fields.Raw(required=True, description="The current meta.json for the IDS") # Known
    }
)
status_message_model = ns.model("Status message",
    {
        "version": fields.String(required=True, description="The version of the IDS"),
        "status": fields.String(required=True, description="The status of the IDS"),
        "training": fields.Raw(required=True, description="The training with progress and description for each device of the IDS"), # Has dynamic mac keys
        "configuration": fields.Nested(status_configuration_model, required=True, description="The used configuration of the IDS"),
        "error_logs": fields.Raw(required=True, description="The error logs in case of errors")
    }
)
status_model = ns.model("Status",
    {
        "result": fields.String(required=True, description="Success/Failed"),
        "message": fields.Nested(status_message_model, required=True, description="The status message. Possible states: Started/Running/Configuring/Analyzing/Exited")
    }
)
# Parser otherwise
config_parser = reqparse.RequestParser()
config_parser.add_argument('callback_url', location='form', type=str, required=True, help='The URL to send the results of the IDS')
config_parser.add_argument('save_threshold_seconds', location='form', type=str, required=True, help='The interval in seconds set by the user for regular analysis attempts')
config_parser.add_argument('allow_training', location='form', type=inputs.boolean, required=True, help='Is training allowed') # Do not use type=bool
config_parser.add_argument('meta_json', location='files', type=FileStorage, required=True, help='The list with device MACs for filtering')

pcap_parser = reqparse.RequestParser()
pcap_parser.add_argument('pcap_name', location='args', type=str, required=True, help='The name of the pcap file')
pcap_parser.add_argument('pcap', location='files', type=FileStorage, required=True, help='The pcap file')


@ns.route("/status")
@api.doc(responses={200: f"Status message", 
                    500: f"Internal Server Error"})
class Status(Resource):
    @ns.marshal_with(status_model)
    def get(self):
        """Returns the status of our environment"""
        try:
            # Collect logs in case of an error
            global logs_send
            error_logs = {}
            if ERROR in get_state():
                if not logs_send:
                    logs = {}
                    for logfile in glob.glob(os.path.join(LOG_DIR, "*.log")): # No old logs
                        logname = os.path.basename(logfile)
                        with open(logfile, "r", encoding="utf-8") as log:
                            logs[logname] = "\n".join(log.readlines()[-5000:]) # Only read the last 5000 lines to keep it reasonable
                    # Compress with gzip and base64 + send logs
                    error_logs = {VERSION: base64.b64encode(gzip.compress(json.dumps(logs).encode("utf-8"))).decode("utf-8")}
                    logs_send = True
            else:
                # Ensure logs_send is False when other states are present
                if logs_send:
                    logs_send = False

            # Load meta.json if it exists 
            meta_json = {}
            if os.path.exists(ids.meta_json):
                with meta_lock:
                    with open(ids.meta_json, "r") as meta_file:
                        try:
                            meta_json = json.load(meta_file)
                        except json.JSONDecodeError:
                            pass

            # Load training_progress.json if it exists
            tmp_training_json = {}
            training_json = {}
            if os.path.exists(ids.training_json):
                with open(ids.training_json, "r") as training_file:
                    try:
                        tmp_training_json = json.load(training_file)
                    except json.JSONDecodeError:
                        pass

            # Filter progress and description
            for mac, info in tmp_training_json.items():
                formatted_mac = mac.replace('-', ':').upper()
                training_json[formatted_mac] = {k: info[k] for k in ('progress', 'description') if k in info}
                progress = training_json[formatted_mac]["progress"]
                training_json[formatted_mac]["progress"] = progress * 100 # Adjust progress for adapter
            tmp_training_json.clear()

            # Return json
            message = {"version": VERSION,
                       "status": get_state(),
                       "training": training_json,
                       "configuration": {"callback_url": ids.callback_url, "save_threshold_seconds": ids.save_threshold_seconds, "allow_training": ids.allow_training, "meta_json": meta_json},
                       "error_logs": error_logs}
            logger.debug(f"Current status: {message}")
            logger.info("Returned current status successfully")

            # Yield before returning
            yield_active_processes()

            return {"result": "Success", "message": message}, 200
        except Exception as e:
            logger.exception(f"API error: {e}")
            set_state(ERROR)
            return {"result": "Failed", "message": str(e)}, 500


@ns.route("/configure")
@api.doc(responses={200: f"Configuration set",
                    415: f"Invalid content type",
                    500: f"Internal Server Error",
                    503: f"{ENV_NAME} unavailable"}, 
         params={"meta_json": {"description": "The list with device MACs for filtering", "type": "file"},
                 "callback_url": {"description": "The URL to send the results of the IDS", "type": "string"},
                 "allow_training": {"description": "Is training allowed", "type": "boolean"}})
class Configuration(Resource):
    @ns.expect(config_parser)
    def post(self):
        """Set configuration values, like the meta_json file, the callback URL or if training is allowed"""
        if ERROR in get_state():
            # IDS has exited, return 503 service unavailable
            return {"result": "Failed", "message": f"{ENV_NAME} has exited, state: {get_state()}"}, 503
        if STARTED in get_state() or RUNNING in get_state() or ANALYZING in get_state():
            try:
                args = config_parser.parse_args()

                # Parse args
                meta_json = args.get('meta_json')
                callback_url = args.get('callback_url')
                save_threshold_seconds = args.get('save_threshold_seconds')
                allow_training = args.get('allow_training')

                # Update config and stop current processes
                ids.update_configuration(callback_url=callback_url, save_threshold_seconds=save_threshold_seconds, allow_training=allow_training)
                
                meta_data = None
                # Attached file
                if "multipart/form-data" in request.content_type:
                    meta_data = json.load(meta_json)
                # File as bytestream
                elif "application/json" in request.content_type:
                    meta_data = request.json
                else:
                    return {"result": "Failed", "message": "Invalid content type"}, 415

                # Write meta_json directly to disk
                with meta_lock:
                    with open(ids.meta_json, "w") as meta_file:
                        if os.path.exists(ids.meta_json):
                            # Flush content if it exist
                            meta_file.write("")
                        json.dump(meta_data, meta_file)
                
                # Change if state is started
                if STARTED in get_state() or ANALYZING in get_state():
                    # Set state to running now
                    set_state(RUNNING)

                logger.debug(f"New configuration: {callback_url=}, {save_threshold_seconds=}, {allow_training=}, {meta_json=}")
                logger.info("New configuration applied successfully")

                # Yield before returning
                yield_active_processes()

                return {"result": "Success", "message": "Configuration set"}, 200
            except Exception as e:
                logger.exception(f"API error: {e}")
                set_state(ERROR)
                return {"result": "Failed", "message": str(e)}, 500
        

@ns.route("/pcap")
@api.doc(responses={200: f"Pcap received, start {ENV_NAME}",
                    400: f"Received invalid pcap data", 
                    409: f"{ENV_NAME} not configured", 
                    415: f"Invalid content type", 
                    429: f"{ENV_NAME} busy", 
                    500: f"Internal Server Error",
                    503: f"{ENV_NAME} unavailable"},
         params={"pcap_name": {"description": "The name of the pcap file", "type": "string"},
                 "pcap": {"description": "The pcap file", "type": "file"}})
class Pcap(Resource):
    @ns.expect(pcap_parser)
    def post(self):
        """Receives pcap data and writes it to the named pipes"""
        if ERROR in get_state():
            # IDS has exited, return 503 service unavailable
            return {"result": "Failed", "message": f"{ENV_NAME} has exited, state: {get_state()}"}, 503
        if STARTED in get_state():
            # IDS is not configured yet, return 409 conflict
            return {"result": "Failed", "message": f"{ENV_NAME} not configured, state: {get_state()}"}, 409
        if ANALYZING in get_state():
            # IDS is analysing or configuring, return 429 too many request
            return {"result": "Failed", "message": f"{ENV_NAME} busy, state: {get_state()}"}, 429
        else:
            try:
                args = pcap_parser.parse_args()

                # Parse args
                pcap_name = args.get('pcap_name')
                pcap = args.get('pcap')

                ids.update_pcap_name(pcap_name)

                pcap_data = None
                # Attached file
                if "multipart/form-data" in request.content_type:
                    pcap_data = pcap.read()
                # File as bytestream
                elif "application/octet-stream" in request.content_type:
                    pcap_data = request.data
                else:
                    return {"result": "Failed", "message": "Invalid content type"}, 415

                # Check if the first 4 bytes are the magic pcap(ng) bytes
                magic_bytes = pcap_data[:4]
                if not (magic_bytes in PCAP_MAGIC_NUMBERS or magic_bytes == PCAPNG_MAGIC_NUMBER):
                    return {"result": "Failed", "message": "Received invalid pcap data"}, 400
                
                # Don't override errors
                if not ERROR in get_state():
                    # Set new state to prevent other calls on /pcap
                    set_state(ANALYZING)

                # Start aggregation before analysis to enable reading pipes first
                ids.start_aggregation()
                time.sleep(1)
                ids.start_analysis()

                # Lock in case of successive pcaps being sent too fast synchronously
                with pipe_lock:
                    with open(ids.rb_pcap_pipe, "wb") as rb_pipe, open(ids.ml_pcap_pipe, "wb") as ml_pipe:
                        
                        # We do one write via request.data instead of chunking the data, as analysis does not 
                        # start asynchronously anyway (not possible in dpkt) and therefore save cpu on many chunked writes.
                        # If memory from sent pcap data becomes an issue, we might look at shared memory solutions instead of pipes

                        # Start load monitoring for max. 10 seconds
                        start_monitoring(timeout=10)

                        rb_pipe.write(pcap_data)
                        ml_pipe.write(pcap_data)

                logger.debug(f"{pcap_data=}")       
                logger.info(f"Pipes written with {len(pcap_data)} bytes from {pcap_name=}")

                # Yield before returning
                yield_active_processes()

                return {"result": "Success", "message": f"Pcap {pcap_name} received, start {ENV_NAME}"}, 200
            except Exception as e:
                logger.exception(f"API error: {e}")
                set_state(ERROR)
                return {"result": "Failed", "message": str(e)}, 500
        

#if __name__ == '__main__':
    #"""
    #Main
    
    #@return: nothing
    #"""
    #logger.info(f"Start Flask API")
    # Does not return after calling
    #app.run(host="0.0.0.0", port=5000)
    #logger.info(f"Finished")
