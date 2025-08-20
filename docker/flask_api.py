#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to start the API 
"""

import os
import logging
import json
import time

from logging.handlers import TimedRotatingFileHandler
from flask import Flask, request
from flask_restx import Api, Resource, fields, reqparse, inputs
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import InternalServerError
from threading import Lock
from kisshome_ids import KisshomeIDS
from states import *

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
# Rotate files each day to max 7 files, oldest will be deleted
fh = TimedRotatingFileHandler(filename="/shared/flask_api.log", when='D', interval=1, backupCount=7, encoding='utf-8', delay=False)
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


# Version
VERSION = "1.1.9"

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

# Initialize Lock for fifo pipes
pipe_lock = Lock()

# Initialize app and make it RESTful
app = Flask(__name__)


def configure_app(flask_app):
    flask_app.config['SWAGGER_UI_DOC_EXPANSION'] = True
    flask_app.config['RESTX_VALIDATE'] = True
    flask_app.config['RESTX_MASK_SWAGGER'] = False
    flask_app.config['ERROR_404_HELP'] = True  # False in prod
    logger.info(f"Start Flask API")


# Configure API
configure_app(app)


ids = None


# Make sure the ids is run as a singleton
@app.before_request
def setup_ids():
    global ids
    if not ids:
        ids = KisshomeIDS()


api = Api(app, version=VERSION, title=f'{ENV_NAME} API',
          description=f'A RESTful API to interact with the {ENV_NAME}')

ns = api.namespace("", description=f"{ENV_NAME} operations")

# Models for JSON like requests or responses
status_configuration_model = ns.model("Status configuration",
    {
        "Callback url": fields.String(required=True, description="The current callback URL of the IDS"),
        "Allow training": fields.Boolean(required=True, description="The current value for allowing training of the IDS"),
        "Meta json": fields.String(required=True, description="The current meta.json of the IDS")
    }
)
status_message_model = ns.model("Status message",
    {
        "Version": fields.String(required=True, description="The version of the IDS"),
        "Status": fields.String(required=True, description="The status of the IDS"),
        "Configuration": fields.Nested(status_configuration_model, required=True, description="The current configuration of the IDS")
    }
)
status_model = ns.model("Status",
    {
        "Result": fields.String(required=True, description="Success/Failed"),
        "Message": fields.Nested(status_message_model, required=True, description="The status message. Possible states: Started/Running/Configuring/Analyzing/Exited")
    }
)
# Parser otherwise
config_parser = reqparse.RequestParser()
config_parser.add_argument('meta_json', location='files', type=FileStorage, required=True, help='The list with device MACs for filtering')
config_parser.add_argument('callback_url', location='form', type=str, required=True, help='The URL to send the results of the IDS')
config_parser.add_argument('allow_training', location='form', type=inputs.boolean, required=True, help='Is training allowed') # Do not use type=bool

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
            # Load meta_json if it exists 
            meta_json = {}
            if os.path.exists(ids.meta_json):
                with open(ids.meta_json, "r") as meta_file:
                    meta_json = json.load(meta_file)
            # Return json
            message = {"Version": VERSION,
                       "Status": get_state(),
                       "Configuration": {"Callback url": ids.callback_url, "Allow training": ids.allow_training, "Meta json": meta_json}}
            logger.debug(f"Current status: {message}")
            return {"Result": "Success", "Message": message}, 200
        except Exception as e:
            set_state(EXITED)
            return {"Result": "Failed", "Message": str(e)}, 500


@ns.route("/configure")
@api.doc(responses={200: f"Configuration set",
                    415: f"Invalid content type", 
                    429: f"{ENV_NAME} busy",
                    500: f"Internal Server Error",
                    503: f"{ENV_NAME} unavailable"}, 
         params={"meta_json": {"description": "The list with device MACs for filtering", "type": "file"},
                 "callback_url": {"description": "The URL to send the results of the IDS", "type": "string"},
                 "allow_training": {"description": "Is training allowed", "type": "boolean"}})
class Configuration(Resource):
    @ns.expect(config_parser)
    def post(self):
        """Set configuration values, like the meta_json file, the callback URL or if training is allowed"""
        if EXITED in get_state():
            # IDS has exited, return 503 service unavailable
            return {"Result": "Failed", "Message": f"{ENV_NAME} has exited, state: {get_state()}"}, 503
        if CONFIGURING in get_state():
            # IDS is configuring, return 429 too many request
            return {"Result": "Failed", "Message": f"{ENV_NAME} busy, state: {get_state()}"}, 429
        if STARTED in get_state() or RUNNING in get_state() or ANALYZING in get_state():
            try:
                args = config_parser.parse_args()

                # Parse args
                meta_json = args.get('meta_json')
                callback_url = args.get('callback_url')
                allow_training = args.get('allow_training')

                # Update config
                ids.update_configuration(callback_url, allow_training)
                
                meta_data = None
                # Attached file
                if "multipart/form-data" in request.content_type:
                    meta_data = json.load(meta_json)
                # File as bytestream
                elif "application/json" in request.content_type:
                    meta_data = request.json
                else:
                    return {"Result": "Failed", "Message": "Invalid content type"}, 415

                # Set state to prevent sending files via /pcap until it is done
                set_state(CONFIGURING)

                # Write meta_json directly to disk
                with open(ids.meta_json, "w") as meta_file:
                    if os.path.exists(ids.meta_json):
                        # Flush content if it exist
                        meta_file.write("")
                    json.dump(meta_data, meta_file)
                
                # Set state to running now
                set_state(RUNNING)

                logger.debug(f"New configuration: callback_url={callback_url}, allow_training={allow_training}, meta_json={meta_json}")

                return {"Result": "Success", "Message": "Configuration set"}, 200
            except Exception as e:
                set_state(EXITED)
                return {"Result": "Failed", "Message": str(e)}, 500
        

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
        if EXITED in get_state():
            # IDS has exited, return 503 service unavailable
            return {"Result": "Failed", "Message": f"{ENV_NAME} has exited, state: {get_state()}"}, 503
        if STARTED in get_state():
            # IDS is not configured yet, return 409 conflict
            return {"Result": "Failed", "Message": f"{ENV_NAME} not configured, state: {get_state()}"}, 409
        if ANALYZING in get_state() or CONFIGURING in get_state():
            # IDS is analysing or configuring, return 429 too many request
            return {"Result": "Failed", "Message": f"{ENV_NAME} busy, state: {get_state()}"}, 429
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
                    return {"Result": "Failed", "Message": "Invalid content type"}, 415

                # Check if the first 4 bytes are the magic pcap(ng) bytes
                magic_bytes = pcap_data[:4]
                if not (magic_bytes in PCAP_MAGIC_NUMBERS or magic_bytes == PCAPNG_MAGIC_NUMBER):
                    return {"Result": "Failed", "Message": "Received invalid pcap data"}, 400
                
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

                        rb_pipe.write(pcap_data)
                        ml_pipe.write(pcap_data)

                        logger.debug(f"Pipes written with {len(pcap_data)} bytes from {pcap_name=}")

                return {"Result": "Success", "Message": f"Pcap {pcap_name} received, start {ENV_NAME}"}, 200
            except Exception as e:
                set_state(EXITED)
                return {"Result": "Failed", "Message": str(e)}, 500
        

#if __name__ == '__main__':
    #"""
    #Main
    
    #@return: nothing
    #"""
    #logger.info(f"Start Flask API")
    # Does not return after calling
    #app.run(host="0.0.0.0", port=5000)
    #logger.info(f"Finished")