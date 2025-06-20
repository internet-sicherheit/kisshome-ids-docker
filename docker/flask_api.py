#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to start the API 
"""

import os
import logging
import json
import time

from flask import Flask, request
from flask_restx import Api, Resource, fields, reqparse
from werkzeug.datastructures import FileStorage
from threading import Lock
from kisshome_ids import KisshomeIDS
from states import *

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
fh = logging.FileHandler("/app/flask_api.log")
sh = logging.StreamHandler()
fh.setLevel(logging.DEBUG)  # set the log level for the log file
fh.setFormatter(formatter)
sh.setFormatter(formatter)
sh.setLevel(logging.INFO)  # set the log level for the console
logger = logging.getLogger(__name__)
logger.addHandler(fh)
logger.addHandler(sh)
logger.setLevel(logging.DEBUG)
logger.propagate = False


# Initialize Lock for fifo pipes
pipe_lock = Lock()
# Initialize app and make it RESTful
app = Flask(__name__)

api = Api(app, version='1.0', title=f'{ENV_NAME} API',
          description=f'A RESTful API to interact with the {ENV_NAME}')
ns = api.namespace("", description=f"{ENV_NAME} operations")
# Models for JSON like requests or responses
status_message_model = ns.model("Status message",
    {
        "Status": fields.String(required=True, description="The status of the IDS"),
        "Has Federated Learning server connection": fields.String(required=True, description="The connection status of the Federated Learning Server")
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
config_parser.add_argument('allow_training', location='form', type=bool, required=True, help='Is training with the Federated Learning Server allowed')

pcap_parser = reqparse.RequestParser()
pcap_parser.add_argument('pcap_name', location='args', type=str, required=True, help='The name of the pcap file')
pcap_parser.add_argument('data', location='files', type=FileStorage, required=True, help='PCAP file')

ids = KisshomeIDS()

            
def configure_app(flask_app):
    flask_app.config['SWAGGER_UI_DOC_EXPANSION'] = True
    flask_app.config['RESTX_VALIDATE'] = True
    flask_app.config['RESTX_MASK_SWAGGER'] = False
    flask_app.config['ERROR_404_HELP'] = True  # False in prod


# Configure API
configure_app(app)


@ns.route("/status")
@api.doc(responses={200: f"Status message", 
                    500: f"Internal Server Error"})
class Status(Resource):
    @ns.marshal_with(status_model)
    def get(self):
        """Returns the status of our environment"""
        try:
            # Return json
            return {"Result": "Success", "Message": {"Status": get_state(), "Has Federated Learning server connection": ids.has_fl_connection()}}, 200
        except Exception as e:
            set_state(EXITED)
            return {"Result": "Failed", "Message": e}, 500


@ns.route("/configure")
@api.doc(responses={200: f"Configuration set", 
                    500: f"Internal Server Error"}, 
         params={"meta_json": {"description": "The list with device MACs for filtering", "type": "json"},
                 "callback_url": {"description": "The URL to send the results of the IDS", "type": "string"},
                 "allow_training": {"description": "Is training with the Federated Learning Server allowed", "type": "boolean"}})
class Configuration(Resource):
    @ns.expect(config_parser)
    def post(self):
        """Set configuration values, like the meta_json file, the callback URL or if training is allowed"""
        try:
            # Set state to prevent sending files via /pcap until it is done
            set_state(CONFIGURING)
            
            args = config_parser.parse_args()

            # Update config
            ids.update_configuration(args['callback_url'], args['allow_training'])
            
            # Write meta_json directly to disk
            if os.path.exists(os.path.join("/app", "meta.json")):
                # Flush content if it exist
                with open(os.path.join("/app", "meta.json"), "w") as meta_file:
                    meta_file.write("")

            with open(os.path.join("/app", "meta.json"), "w") as meta_file:
                meta_json = args['meta_json']
                json.dump(json.load(meta_json), meta_file)
            
            # Set state to running now
            set_state(RUNNING)

            return {"Result": "Success", "Message": "Configuration set"}, 200
        except Exception as e:
            set_state(EXITED)
            return {"Result": "Failed", "Message": e}, 500
        

@ns.route("/pcap")
@api.doc(responses={200: f"Pcap received, start {ENV_NAME}", 
                    400: f"Not configured",  
                    429: f"{ENV_NAME} busy", 
                    500: f"Internal Server Error"},
         params={"pcap_name": {"description": "The name of the pcap file", "type": "string"}})
class Pcap(Resource):
    @ns.expect(pcap_parser)
    def post(self):
        """Receives pcap data and writes it to the named pipes"""
        if STARTED in get_state():
            # IDS is not configured yet, return 400
            return {"Result": "Failed", "Message": f"Not configured, state: {get_state()}"}, 400
        if ANALYZING in get_state() or CONFIGURING in get_state():
            # IDS is analysing or configuring, return 429 too many request
            return {"Result": "Failed", "Message": f"{ENV_NAME} busy, state: {get_state()}"}, 429
        else:
            try:
                pcap_name = request.args.get('pcap_name')
                ids.update_pcap_name(pcap_name)

                # Start aggregation before analysis to enable reading pipes first
                ids.start_aggregation()
                time.sleep(1)
                ids.start_analysis()

                # Set new state to prevent other calls on /pcap
                set_state(ANALYZING)

                # Lock in case of successive pcaps being sent too fast synchronously
                with pipe_lock:
                    with open(ids.rb_pcap_pipe, "wb") as rb_pipe, open(ids.ml_pcap_pipe, "wb") as ml_pipe:
                        
                        # We do one write via request.data instead of chunking the data, as analysis does not 
                        # start asynchronously anyway (not possible in dpkt) and therefore save cpu on many chunked writes.
                        # If memory from sent pcap data becomes an issue, we might look at shared memory solutions instead of pipes

                        pcap = None
                        if "application/octet-stream" in request.content_type:
                            pcap = request.data
                        if "multipart/form-data" in request.content_type:
                            pcap = request.files['data'].read()
                        else:
                            raise Exception(f"Pcap data for {pcap_name} not found")

                        rb_pipe.write(pcap)
                        ml_pipe.write(pcap)

                return {"Result": "Success", "Message": f"Pcap {pcap_name} received, start {ENV_NAME}"}, 200
            except Exception as e:
                set_state(EXITED)
                return {"Result": "Failed", "Message": e}, 500


log_ns = api.namespace("log", description=f"{ENV_NAME} logs") 
@log_ns.route("")
@api.doc(responses={200: f"Ok", 
                    500: f"Internal Server Error"})
class Log(Resource):
    def get(self):
        """Returns the contents of the log files as a json"""
        result_json = {}
        try:
            if os.path.exists("/app/kisshome_ids.log"):
                with open("/app/kisshome_ids.log", "r") as kisshome_ids_log:
                    result_json["kisshome_ids"] = kisshome_ids_log.readlines()
            else:
                result_json["kisshome_ids"] = None
            if os.path.exists("/app/aggregator.log"):
                with open("/app/aggregator.log", "r") as aggregator_log:
                    result_json["aggregator"] = aggregator_log.readlines()
            else:
                result_json["aggregator"] = None
            if os.path.exists("/app/rb_analysis.log"):
                with open("/app/rb_analysis.log", "r") as rb_log:
                    result_json["rb"] = rb_log.readlines()
            else:
                result_json["rb"] = None
            if os.path.exists("/app/ml_analysis.log"):
                with open("/app/ml_analysis.log", "r") as ml_log:
                    result_json["ml"] = ml_log.readlines()
            else:
                result_json["ml"] = None
            if os.path.exists("/app/flask_api.log"):
                with open("/app/flask_api.log", "r") as api_log:
                    result_json["api"] = api_log.readlines()
            else:
                result_json["api"] = None
            return {"Result": "Success", "Message": result_json}, 200
        except Exception as e:
            set_state(EXITED)
            return {"Result": "Failed", "Message": e}, 500
        

if __name__ == '__main__':
    """
    Main

    @return: nothing
    """
    logger.info(f"Start Flask API")
    # Does not return after calling
    app.run(host="0.0.0.0", port=5000)
    logger.info(f"Finished")