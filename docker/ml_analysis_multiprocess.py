
#!/usr/bin/env python3

import sys
import time
import json
import dpkt
import traceback
import numpy as np
import logging
import csv
import struct
import bisect
import ipaddress
import random

from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import lru_cache
from collections import defaultdict, deque
from multiprocessing import Pool, cpu_count
from states import set_state, EXITED

########################################
# 0) Set up logging and load our known device MAC addresses
########################################

# 
logger = None

def init_logger():

    global logger

    # Each log line includes the date and time, the log level, the current function and the message
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
    # The log file is the same as the module name plus the suffix ".log"
    # Rotate files each day to max 7 files, oldest will be deleted
    fh = TimedRotatingFileHandler(filename="/shared/ml_analysis.log", when='D', interval=1, backupCount=7, encoding='utf-8', delay=False)
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

KNOWN_DEVICES_JSON_FILE = None

# 
known_macs = None

def load_known_device_json():
    global known_macs

    try:
        with open(KNOWN_DEVICES_JSON_FILE, "r") as f:
            known_devices_data = json.load(f)
            # Suppose meta.json is a mapping { "mac": "desc", ... }
            known_macs = {bytes.fromhex(mac.replace(":", "")) for mac in known_devices_data.keys() }
            
    except FileNotFoundError:
        set_state(EXITED)
        logger.info("WARNING: meta.json not found. Direction detection won't work.")
        known_macs = set()

    except Exception as e:
        set_state(EXITED)
        logger.info(f"An unexpected error occurred: {str(e)}")
        sys.exit()

COUNTRY_RECOGNITION_CSV_FILE = "/config/ip_to_country.csv"
ASN_RECOGNITION_CSV_FILE = "/config/ip_to_asn.csv"

# Global list of (start_int, end_int, country)
ip_to_country_ranges = []
ip_to_asn_ranges = []

def load_country_recognition():
    """
    Load IP ranges and their country codes from a CSV file.
    The file is assumed to have three columns: start_ip_int, end_ip_int, country_code.
    Already sorted, gapless ranges. 
    Returns a list of (start_int, end_int, country) sorted by start_int.
    """
    global ip_to_country_ranges

    with open(COUNTRY_RECOGNITION_CSV_FILE, 'r', newline='') as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            start_int = int(row[0].strip())
            end_int = int(row[1].strip())
            country = row[2].strip()
            ip_to_country_ranges.append((start_int, end_int, country))

def load_asn_recognition():
    """
    Load IP ranges and their autonomous system numbers from a CSV file.
    The file is assumed to have three columns: start_ip_int, end_ip_int, asn.
    Already sorted, gapless ranges. 
    Returns a list of (start_int, end_int, asn) sorted by start_int.
    """
    global ip_to_asn_ranges

    with open(ASN_RECOGNITION_CSV_FILE, 'r', newline='') as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            start_int = int(row[0].strip())
            end_int = int(row[1].strip())
            try:
                asn = int(row[2].strip())
            
            except:
                asn = -1
            ip_to_asn_ranges.append((start_int, end_int, asn))

def setup():

    init_logger()
    load_known_device_json()
    load_country_recognition()
    load_asn_recognition()


########################################
# 1) Packet Detail Extraction
########################################

# Basic attribute extraction
# TODO: possibly outsource to different module (possibly flow extraction too) 
# TODO: ensure quality of packets
# i.e. all packets need to be checked for validity and filtered if outliers are detected.
# Then, no certainty measures (details.get(_, default_value)) will be necessary
# TODO: skip dictionary if not needed anymore. change to tuple (more lightweight), skip everything not needed

@lru_cache(maxsize=10000)
def get_country(ip_int):
    """
    Given an IP address as a integer, return the matching country code
    using a binary search over 'ip_to_country_ranges' for O(log n)
    
    Results are cached, so repeated calls of the same ip_int work at O(1)

    If no matching range is found, returns "Unknown".
    Also prints the IP in dotted form and the result for demonstration.
    """

    default_country_value = "Unknown"

    # ip_int = struct.unpack("!I", ip_byte)[0] # now obsolte: in case ip comes in byte format
    if ip_int < 0:
        return default_country_value  # ip_int is smaller than any start in sorted_ranges

    # Use bisect to find the rightmost range whose start <= ip_int in O(log n)
    idx = bisect.bisect_right(ip_to_country_ranges, (ip_int, float('inf'), float('inf'))) - 1

    try:
        start_int, end_int, country = ip_to_country_ranges[idx]
        if start_int <= ip_int <= end_int:
            return country
        else:
            return default_country_value 
    
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"{idx=} {ip_int=}")
        raise

@lru_cache(maxsize=10000)
def get_asn(ip_int):
    """
    Given an IP address as a integer, return the matching asn
    using a binary search over 'ip_to_asn_ranges' for O(log n)
    
    Results are cached, so repeated calls of the same ip_int work at O(1)

    If no matching range is found, returns "Unknown".
    Also prints the IP in dotted form and the result for demonstration.
    """
    default_asn_value = -1

    # ip_int = struct.unpack("!I", ip_byte)[0] # now obsolte: in case ip comes in byte format
    if ip_int < 0:
        return default_asn_value  # ip_int is smaller than any start in sorted_ranges

    # Use bisect to find the rightmost range whose start <= ip_int in O(log n)
    idx = bisect.bisect_right(ip_to_asn_ranges, (ip_int, float('inf'), float('inf'))) - 1

    try:
        start_int, end_int, asn = ip_to_asn_ranges[idx]
        if start_int <= ip_int <= end_int:
            return asn
        else:
            return default_asn_value
    
    except Exception as e:
        set_state(EXITED)
        logger.exception(f"{idx=} {ip_int=}")
        raise

def extract_details(packet):
    """
    Parse link, IP, and possibly TCP/UDP from a pcap tuple (ts, buf).
    Return a dict of fields or None if parsing fails.
    """
    ts, buf = packet

    # ethernet protocol
    eth = dpkt.ethernet.Ethernet(buf)

    details = {
        "packet_timestamp": ts,
        "packet_length": len(buf),
        "src_mac": eth.src, # ':'.join(['%02x' % b for b in eth.src]).lower(),
        "dst_mac": eth.dst, # ':'.join(['%02x' % b for b in eth.dst]).lower(),
        "link_protocol": eth.type
    }

    if not isinstance(eth.data, dpkt.ip.IP):
        return details  # e.g., ARP or something else

    # ip protocol
    ip = eth.data
    ip_header_len = ip.hl * 4
    ip_total_len = ip.len
    ip_payload_size = ip_total_len - ip_header_len

    details.update({
        "network_protocol": ip.p,
        "src_ip": struct.unpack("!I", ip.src)[0],
        "dst_ip": struct.unpack("!I", ip.dst)[0],
        "ip_header_size": ip_header_len,
        "ip_payload_size": ip_payload_size
    })

    # transport protocol
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        details["transport_protocol"] = "TCP"
        details["src_port"] = tcp.sport
        details["dst_port"] = tcp.dport
        transport_header_size = tcp.off * 4
        transport_payload_size = len(tcp.data)
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        details["transport_protocol"] = "UDP"
        details["src_port"] = udp.sport
        details["dst_port"] = udp.dport
        transport_header_size = 8
        transport_payload_size = len(udp.data)
    else:
        details["transport_protocol"] = f"Proto_{ip.p}"
        details["src_port"] = 0
        details["dst_port"] = 0
        transport_header_size = 0
        transport_payload_size = 0

    details["transport_header_size"] = transport_header_size
    details["transport_payload_size"] = transport_payload_size

    # additional features TODO both known // both local ??
    if details["src_mac"] in known_macs:
        details["direction"] = "outgoing"
        details["country"] = get_country(details.get('dst_ip'))
        details["asn"] = get_asn(details.get('dst_ip'))
        #todo logger.info(details["asn"])

    elif details["dst_mac"] in known_macs:
        details["direction"] = "incoming"
        details["country"] = get_country(details.get('src_ip'))
        details["asn"] = get_asn(details.get('src_ip'))

    else:
        logger.debug(f"Both source and dst mac are unknown: {details.get('src_mac')=}, {details.get('dst_mac')=}. This should probably not happen")
        # TODO: do nothing here
        # TODO: both are in known macs?
        details["direction"] = -1

    return details


########################################
# 2) Flow Tracking and Feature Scaling
########################################

# TODO: rework flow tracking
# if model is flow based, batches have to be build across uploaded pcaps, requiring major rework.
# same goes for choosing device type specificity (i.e. one process might be responsible for one device type model)

FLOW_TIMEOUT_INTERVAL = 60.0 * 60.0 * 1.0 # one hour 

# We keep flows tracked via last seen packet as well as each packet's feature vector
# TODO: the latter is not used yet, but will be once we have a sophisticated model
flows = defaultdict(lambda: {
    "last_ts": None,
    "packets": deque(maxlen=200)
    
})

def prune_flows(timeout):
    now = time.time()
    remove_keys = []
    for fk, data in flows.items():
        lst = data["last_ts"]
        if lst and (now - lst) > timeout:
            remove_keys.append(fk)
    for rk in remove_keys:
        del flows[rk]
    
def get_flow_key(packet_details):
    """
    We can define a "flow" primarily by (transport_protocol, src_ip, src_port, dst_ip, dst_port).
    """
    return (
        packet_details.get('transport_protocol'),
        packet_details.get('src_ip'),
        packet_details.get('src_port'),
        packet_details.get('dst_ip'),
        packet_details.get('dst_port')
    )

# We need min/max values for scaling (normalizing) the feature vectors
# TODO: We might change this later to a better preprocessing (z-scaling or so)
FEATURE_MIN_ARR = np.array([20, 8, 0, 40, 0, 0, 0.0, -1.0], dtype=np.float32)
FEATURE_MAX_ARR = np.array([60, 60, 1500, 1500, 65535, 65535, 2.0, 1.0], dtype=np.float32)

def scale_feature_vector_batch(raw_batch):
    np_batch = np.array(raw_batch, dtype=np.float32)
    scaled_arrays = (np_batch - FEATURE_MIN_ARR) / (FEATURE_MAX_ARR - FEATURE_MIN_ARR)
    # clamp or handle edge cases
    clipped_batch = np.clip(scaled_arrays, 0.0, 1.0)

    return clipped_batch

def build_feature_vector(details):
    flow_key = get_flow_key(details)
    current_ts = details["packet_timestamp"]

    last_ts = flows[flow_key]["last_ts"]
    if last_ts is None:
        interarrival_time = 0.0
    else:
        interarrival_time = current_ts - last_ts
    flows[flow_key]["last_ts"] = current_ts

    ip_header_size = details.get("ip_header_size", 0)
    transport_header_size = details.get("transport_header_size", 0)
    transport_payload_size = details.get("transport_payload_size", 0)
    packet_length = details.get("packet_length", 0)
    src_port = details.get("src_port", 0)
    dst_port = details.get("dst_port", 0)
    direction = details.get("direction", -1)
    if direction == "outgoing":
        direction = 1
    elif direction == "incoming":
        direction = 0

    raw_feature_vector = [
        ip_header_size,
        transport_header_size,
        transport_payload_size,
        packet_length,
        float(src_port),
        float(dst_port),
        interarrival_time,
        float(direction)
    ]

    # Not strictly required, but we do store it in flows for reference for now
    flows[flow_key]["packets"].append({"ts": current_ts, "features": raw_feature_vector})

    return raw_feature_vector

########################################
# 3) Model and Multiprocessing Setup
########################################

NUM_INFERENCE_PROCESSES = cpu_count() - 1 #3

model = None  # Will be set by each worker during init

def init_worker():

    # Make sure every worker loads tf while the reader process does not
    from tensorflow.keras import Input, layers, Model
    
    def build_keras_model():
        input_dim = 8
        inputs = Input(shape=(input_dim,))
        x = layers.Dense(256, activation='relu')(inputs)
        x = layers.Dense(256, activation='relu')(x)
        outputs = layers.Dense(1, activation='sigmoid')(x)
        model = Model(inputs=inputs, outputs=outputs)
        model.compile(optimizer='adam', loss='binary_crossentropy')
        return model

    # Each process loads its own model
    global model

    # TODO: some more complicated logic to have worker dependant different models (i.e. device type specific)
    model = build_keras_model()

# The worker function runs in a separate process
def batched_inference(fv_batch):
    global model

    arr = np.array(fv_batch, dtype=np.float32)
    scores = model.predict(arr, verbose=0).flatten().tolist()
    
    return scores

########################################
# 4) Main Packet-Processing
########################################

# Batched inference to significantly increase performance
BATCH_SIZE = 128

def process_packets(pool, pcap):
    start_time = time.time()

    try:
        packet_count = 0
        pcap_size = 0

        futures = []
        batch_feature_vectors = []

        user_device_statistics = {key: {"external_ips": {}, "data_volume": {"packet_count": 0, "data_volume_bytes": 0}} for key in known_macs}

        for packet in pcap:

            details = extract_details(packet)
            if not details:
                # skip if we can't parse
                # TODO: here we may do some outlier detection or other
                continue
            
            logger.debug(f"{details=}")

            # Save necessary infos for user statistics
            if int(details["link_protocol"]) == 2048: # Only ipv4
                
                if details["direction"] == "outgoing":
                    device_statistics = user_device_statistics[details["src_mac"]]
                    if details["dst_ip"] not in device_statistics["external_ips"]:
                        device_statistics["external_ips"][details["dst_ip"]] = {"country": details["country"], "data_volume_bytes": 0}
                    device_statistics["external_ips"][details["dst_ip"]]["data_volume_bytes"] += details["packet_length"]
                    device_statistics["data_volume"]["packet_count"] += 1
                    device_statistics["data_volume"]["data_volume_bytes"] += details["packet_length"]

                elif details["direction"] == "incoming":
                    device_statistics = user_device_statistics[details["dst_mac"]]
                    if details["src_ip"] not in device_statistics["external_ips"]:
                        device_statistics["external_ips"][details["src_ip"]] = {"country": details["country"], "data_volume_bytes": 0}
                    device_statistics["external_ips"][details["src_ip"]]["data_volume_bytes"] += details["packet_length"]
                    device_statistics["data_volume"]["packet_count"] += 1
                    device_statistics["data_volume"]["data_volume_bytes"] += details["packet_length"]

            else:
                pass  # TODO: Handle other packet types like multicast, etc.

            # Accumulate for batched ML processing
            raw_feature_vector = build_feature_vector(details)
            batch_feature_vectors.append(raw_feature_vector)

            if len(batch_feature_vectors) >= BATCH_SIZE:
                # Scale feature vectors in batch for performance
                processed_feature_vectors = scale_feature_vector_batch(batch_feature_vectors)

                # Once we have BATCH_SIZE, send the batch to the task queue
                fut = pool.apply_async(batched_inference, (processed_feature_vectors,))
                futures.append(fut)
                batch_feature_vectors.clear()

            packet_count += 1
            pcap_size += details["packet_length"]
           

        # After finishing all packets, we may have a partial batch
        if batch_feature_vectors:
            processed_feature_vectors = scale_feature_vector_batch(batch_feature_vectors)
            fut = pool.apply_async(batched_inference, (processed_feature_vectors, ))
            futures.append(fut)

        # Aggregate results of all tasks, waiting for unfinishes task results
        all_results = []
        for fut in futures:
            batch_result = fut.get()  # This is one entire batch
            all_results.extend(batch_result)

        logger.info(f"\nDone processing pcap. \n Processed {packet_count} packets. \n Avg packet analysis time: {(time.time() - start_time) / packet_count:.6f}s")

        # TODO: Do something with the inference score other than returning them
        
        return user_device_statistics, all_results, packet_count, pcap_size

    except Exception as e:
        set_state(EXITED)
        traceback.print_exc()
        logger.exception(f"An unexpected error occurred: {str(e)}")
        raise

########################################
# 5) Main
########################################

#PCAP_PIPE_PATH = "/pipe/ml_pcap_pipe"

#RESULT_PIPE_PATH = "/pipe/ml_result_pipe"

#RESULT_FILE = "/app/ml_results.txt"

def flush_results(result_pipe, results, device_statistics, analysis_duration_ms, packet_count, pcap_size):
    """
    Overwrite ml_results.txt with new results (one line per score).
    """
    result_text = ""
    formatted_devices = []

    # TODO: TEST!!!

    detections = []

    index = 0
    for score in results:
        #result_text += f"{score}\n"
        # if score > 0.8:
        #     alert = {
        #         "type": "Alert", 
        #         "description": "Anomaly detected", 
        #         "first_occurrence": "TODO", # TODO: Only scores available here
        #         "number_occurrences": 1, # Start with 1
        #         "score": score
        #     }
        #     detections.append({"mac": "TODO", "ml": [alert]})
        #
        # ^: No alerts for ml
        #
        mac_keys = list(device_statistics.keys())
        if index < len(mac_keys):
            mac_bytes = mac_keys[index]
            mac = ":".join(f"{b:02x}" for b in mac_bytes).upper()
            stats = device_statistics[mac_bytes]
        else:
            continue # Just testing

        test_occurrence = random.randint(1, 100) # TODO: Showcase

        test_threshold = 0.5

        if score > test_threshold:
            alert = {
                "type": "Alert", 
                "description": f"{test_occurrence} Anomalies detected",
                "first_occurrence": str(datetime.now(ZoneInfo("Europe/Berlin")).isoformat()),
                "number_occurrences": test_occurrence # Random
            }
            detections.append({"mac": mac, "ml": alert})
        elif score <= test_threshold:
            normal = {
                "type": "Normal", 
                "description": f"{test_occurrence} Anomalies detected", 
                "first_occurrence": str(datetime.now(ZoneInfo("Europe/Berlin")).isoformat()),
                "number_occurrences": test_occurrence # Random
            }
            detections.append({"mac": mac, "ml": normal})
        index += 1
        #logger.debug(f"{score}\n")

    for mac, stats in device_statistics.items():
        mac_str = ":".join(['%02x' % b for b in mac]).upper()
        external_ips = {
            str(ipaddress.ip_address(ip)): country
            for ip, country in stats['external_ips'].items()
        }
        formatted_devices.append({
            "mac": mac_str,
            "external_ips": external_ips,
            "data_volume": stats["data_volume"]
        })

    result_data = {
        "detections": detections,
        "statistics": {
            "analysisDurationMs": analysis_duration_ms,
            "totalBytes": pcap_size,
            "packets": packet_count,
            "devices": formatted_devices
        }
    }

    #result_text += "\n" + json.dumps(result_data, indent=4)
    result_text = json.dumps(result_data, indent=4)

    #with open(RESULT_FILE, "w") as fw:
        #fw.write(result_text)

    with open(result_pipe, "w") as fw:
        fw.write(result_text)

def start_analysis(pool, pcap_pipe, result_pipe):
    # Outer loop: repeatedly wait for new pcap data
    logger.info("Starting ml inference script")

    while True:
        logger.info("ML analysis: Waiting for next pcap...")

        # 1) Open the pipe in blocking mode
        #    This call will block until the *writer* actually opens the pipe and writes data
        with open(pcap_pipe, "rb") as fifo:
            start_time = time.time()
            logger.info("ML analysis: Reading full pcap from pipe...")

            try:
                pcap_reader = dpkt.pcap.Reader(fifo)
                device_statistics, results, packet_count, pcap_size = process_packets(pool, pcap_reader)

                # We prune flows after a pcap has been read, and according to if flows are now too old according to FLOW_TIMEOUT_INTERVAL.
                # This guarantees that we don't prune flows that have been still ongoing (since we do it after reading the latest pcap)
                # while also guaranteeing that pruning isn't tied to the pcap_sending interval (due to FLOW_TIMEOUT_INTERVAL).
                prune_flows(FLOW_TIMEOUT_INTERVAL)

                analysis_duration_ms = time.time() - start_time

                # TODO: for now we just do a file write, we need to change this -> Pipes (resolved?)
                flush_results(result_pipe, results, device_statistics, analysis_duration_ms * 1000, packet_count, pcap_size)

                logger.info(f"PCAP Analysis took {analysis_duration_ms}s")

            except dpkt.NeedData:
                # Means dpkt tried to parse data but it didn't exist or was incomplete
                set_state(EXITED)
                logger.exception(f"NeedData error:  => Got empty or truncated pcap.")

            except dpkt.UnpackError as e:
                # If the pcap header is corrupt or there's some other parse error
                set_state(EXITED)
                logger.exception("Pcap parse error - invalid or corrupted pcap")

            except Exception as e:
                set_state(EXITED)
                logger.exception(f"Unknown error parsing pcap: {e}")
            
# if __name__ == "__main__":
def ml_analyze(pcap_pipe, result_pipe, meta_json, allow_training):
    # Set up global meta.json path
    global KNOWN_DEVICES_JSON_FILE
    if not KNOWN_DEVICES_JSON_FILE:
        KNOWN_DEVICES_JSON_FILE = meta_json

    # Do setup to init every component
    setup()

    # TODO: Create usage for this var
    logger.debug(f"{allow_training=}")

    logger.info("Starting ml worker processes")
    # Start worker PROCESSES
    pool = Pool(
        processes=NUM_INFERENCE_PROCESSES,
        initializer=init_worker#,
        #initargs=("?",)  # optional arguments to init_worker
    )
    logger.info("ml worker processes started")

    try:
        start_analysis(pool, pcap_pipe, result_pipe)

        pool.close()
        pool.join()

    # Make sure that processes are stopped even through Ctrl + C or otherwise
    except Exception as e:
        set_state(EXITED)
        logger.exception("Unknown error")

        pool.close()
        pool.join()
        





"""

Todos:

first check multicast / broadcast. if these, dont check for country/asn. if ip even further out, need default values



Further speedups:

    tensorflow lite:

        Train model in regular TF on a more powerful machine, then
        convert it to a .tflite file with the TF Lite Converter:
            converter = tf.lite.TFLiteConverter.from_keras_model(your_keras_model)
            tflite_model = converter.convert()
            with open("model.tflite", "wb") as f:
                f.write(tflite_model)

        On the Pi, install the tensorflow-lite runtime:
            pip install tflite-runtime

        Load and run inferences via the TF Lite interpreter:
            import tflite_runtime.interpreter as tflite
            interpreter = tflite.Interpreter(model_path="model.tflite")
            interpreter.allocate_tensors()
            # Get input/output details, then feed input data, invoke(), read outputs

    floating point precision: change from 32 bit (or what it is) to 16 or 8, significant CPU and RAM opti


"""
