
#!/usr/bin/env python3

import sys
import time
import json
import dpkt
import numpy as np

from collections import defaultdict, deque
from tensorflow import keras
from tensorflow.keras import layers

import logging

# Each log line includes the date and time, the log level, the current function and the message
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s")
# The log file is the same as the module name plus the suffix ".log"
fh = logging.FileHandler("/app/ml_analysis.log")
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

PIPE_PATH = "/app/ml_pcap_pipe"

"""
1) read from stdin (pcap data via tcpdump).
2) parse each packet with dpkt to extract header info
3) maintain a 'last packet timestamp' for each flow in order to compute interarrival time.
4) determine direction (outgoing=1, incoming=0) by comparing MAC addresses with a list of known devices.
5) build a feature vector for each packet and run it through a minimal Keras model.
"""

# ------------------------------------------------------
# 0) Load our known device MAC addresses
# ------------------------------------------------------

known_macs = None

try:
    with open("app/devices.json", "r") as f:
        known_devices_data = json.load(f)
        # Suppose devices.json is a mapping { "mac": "desc", ... }
        known_macs = {bytes.fromhex(mac.replace(":", "")) for mac in known_devices_data.keys() }
        
except FileNotFoundError:
    print("WARNING: devices.json not found. Direction detection won't work.")
    known_macs = set()

except Exception as e:
    print(f"An unexpected error occurred: {str(e)}")
    sys.exit()


# ------------------------------------------------------
# 1) Minimal Keras Model Setup
#    (Replace with your actual trained model if you have one)
# ------------------------------------------------------

# Simple feed-forward network that expects an input vector with example features:
#   0) ip_header_size
#   1) transport_header_size
#   2) transport_payload_size
#   3) packet_length
#   4) src_port
#   5) dst_port
#   6) interarrival_time
#   7) direction (1=outgoing, 0=incoming, or -1 if unknown)

input_dim = 8

# Define the input layer
inputs = keras.Input(shape=(input_dim,))

# Connect each layer
x = layers.Dense(256, activation='relu')(inputs)
x = layers.Dense(256, activation='relu')(x)
outputs = layers.Dense(1, activation='sigmoid')(x)  # i.e. anomaly score in [0,1]

# Create the model by specifying the inputs and outputs
model = keras.Model(inputs=inputs, outputs=outputs)

# For demonstration, we'll just compile with a dummy loss
model.compile(optimizer='adam', loss='binary_crossentropy')

def run_batch_inference(feature_vectors):
    """
    Run the feature vector through the Keras model to produce an anomaly score.
    """
    x = np.array(feature_vectors, dtype=np.float32)  # shape (BATCH_SIZE, 8)
    scores = model.predict(x, verbose=0)
    # Assuming 'scores' is a numpy array shape (BATCH_SIZE, 1). We return a list of floats.
    return scores.flatten().tolist()

# ------------------------------------------------------
# 2) Flow tracking for interarrival time
#    We'll store the last timestamp seen for each flow.
# ------------------------------------------------------

FLOW_TIMEOUT_INTERVAL = 60.0 * 60.0 * 1.0 # one hour 

# Each flow has a deque of up to 200 packets
flows = defaultdict(lambda: {
    "packets": deque(maxlen=200), 
    "last_ts": None
})

def prune_flows(timeout):
    """
    Remove flows that haven't been updated in the last `timeout` seconds.
    We use flow_data["last_ts"] to store the last real-time update (time.time()).
    """
    now = time.time()
    to_remove = []
    for flow_key, flow_data in flows.items():
        last_ts = flow_data["last_ts"]
        if last_ts is not None and (now - last_ts) > timeout:
            to_remove.append(flow_key)
    for flow_key in to_remove:
        del flows[flow_key]

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
# ------------------------------------------------------
# 3) Packet Parsing
#    We'll extract:
#      - IP header length
#      - Transport header length
#      - Transport payload length
#      - Entire packet length
#      - Direction
#      - Interarrival time (based on flow's last timestamp)
# ------------------------------------------------------

def extract_details(packet):
    """
    Parse link, IP, and possibly TCP/UDP from a pcap tuple (ts, buf).
    Return a dict of fields or None if parsing fails.
    """
    ts, buf = packet
    eth = dpkt.ethernet.Ethernet(buf)
    details = {
        "packet_timestamp": ts,
        "packet_length": len(buf),
        "src_mac": eth.src, # ':'.join(['%02x' % b for b in eth.src]).lower(),
        'dst_mac': eth.dst, # ':'.join(['%02x' % b for b in eth.dst]).lower(),
        "link_protocol": eth.type
    }

    if not isinstance(eth.data, dpkt.ip.IP):
        return details  # e.g., ARP or something else

    ip = eth.data
    ip_header_len = ip.hl * 4
    ip_total_len = ip.len
    ip_payload_size = ip_total_len - ip_header_len

    details.update({
        "network_protocol": ip.p,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ip_header_size": ip_header_len,
        "ip_payload_size": ip_payload_size
    })

    # transport
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

    # TODO: both in known macs?
    if details.get('src_mac') in known_macs:
        details['direction'] = 1
    elif details.get('dst_mac') in known_macs:
        details['direction'] = 0
    else:
        details['direction'] = -1

    return details

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
    direction = details.get("direction", 0)

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

    # Not strictly required, but we do store it in flows for reference
    flows[flow_key]["packets"].append({"ts": current_ts, "features": raw_feature_vector})

    return raw_feature_vector

# ------------------------------------------------------
# 4) Main Packet-Processing Loop
# ------------------------------------------------------

# Batched inference to significantly increase performance
BATCH_SIZE = 128

def process_packets(pcap):
    start_time = time.time()

    try:
        packet_count = 0

        batch_feature_vectors = []

        all_results = []

        for packet in pcap:
            
            details = extract_details(packet)
            # If parsing fails or we got no details, we cant continue            
            if details:
                
                feature_vector = build_feature_vector(details)
                batch_feature_vectors.append(feature_vector)

                if len(batch_feature_vectors) >= BATCH_SIZE:
                    processed_feature_vectors = scale_feature_vector_batch(batch_feature_vectors)
                    scores = run_batch_inference(processed_feature_vectors)
                    all_results.extend(scores)
                    batch_feature_vectors.clear()

            packet_count += 1

        # After finishing all packets, we may have a partial batch
        if batch_feature_vectors:
            processed_feature_vectors = scale_feature_vector_batch(batch_feature_vectors)
            scores = run_batch_inference(processed_feature_vectors)
            all_results.extend(scores)
            
        logger.info(f"\nDone processing pcap. \n Processed {packet_count} packets. \n Avg packet analysis time: {(time.time() - start_time) / packet_count:.6f}s")

        return all_results
    
    except KeyboardInterrupt:
        sys.exit()

# ------------------------------------------------------
# 5) Entry point
# ------------------------------------------------------

#RESULT_FILE = "/app/ml_results.txt"

def flush_results(result_pipe, results):
    """
    Overwrite ml_results.txt with new results (one line per score).
    """
    with open(result_pipe, "w") as fw:
        # Just write one item per line:
        for score in results:
            fw.write(f"{score}\n")

def ml_analyze(pcap_pipe, result_pipe, allow_training):
    # TODO: Create usage for this var
    logger.debug(f"{allow_training=}")

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
                results = process_packets(pcap_reader)
                flush_results(result_pipe, results)

                prune_flows(FLOW_TIMEOUT_INTERVAL)

                logger.info(f"PCAP Analysis took {time.time() - start_time}s")

            except dpkt.NeedData:
                # Means dpkt tried to parse data but it didn't exist or was incomplete
                logger.exception(f"NeedData error:  => Got empty or truncated pcap.")

            except dpkt.UnpackError as e:
                # If the pcap header is corrupt or there's some other parse error
                logger.exception("Pcap parse error - invalid or corrupted pcap")

            except Exception as e:
                logger.exception(f"Unknown error parsing pcap: {e}")
            