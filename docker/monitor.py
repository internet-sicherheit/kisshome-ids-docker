#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to monitor system resources of our environment, the Kisshome IDS system
"""

import os
import shlex
import subprocess
import threading
import signal
import time

# Directory to save the monitor data
SYSSTAT_DIRECTORY = "/stat"
# Timer to stop monitoring automatically
TIMER = None
# Monitoring process lists with tuples <process, fd>
PROCESSES = []


def get_cpuinfo():
    """
    Run lscpu | grep name to get the cpu information

    @return: string with cpu info
    """
    cmd = f"lscpu | grep name"
    lscpu_process = subprocess.run(cmd, capture_output=True, shell=True)
    if lscpu_process.returncode != 0:
        # Something went wrong
        raise Exception(lscpu_process) 
    else:
        return lscpu_process.stdout


def get_gpuinfo():
    """
    Run lspci | grep VGA to get the gpu information

    @return: string with gpu info
    """
    cmd = f"lspci | grep VGA"
    lspci_process = subprocess.run(cmd, capture_output=True, shell=True)
    if lspci_process.returncode != 0:
        # Something went wrong
        raise Exception(lspci_process) 
    else:
        return lspci_process.stdout


def start_monitoring(interval=1, timeout=None):
    """
    Start monitoring system usage by using sysstat methods

    @param prefix: Is used to specify who is using it as a string, e.g. "rb" or "ml"
    @param interval: The monitoring interval in seconds as an int, default 1
    @param tiemout: Timeout for the operation as an int, default None
    @return: nothing
    """
    global PROCESSES
    global TIMER

    # Use Popen() for parallel monitoring
    # Also use fd for output handling
    iostat_cmd = f"iostat -x {interval} -o JSON"
    iostat_fd = open(os.path.join(SYSSTAT_DIRECTORY, "iostat.json"), "w")
    PROCESSES.append((subprocess.Popen(shlex.split(iostat_cmd), stdout=iostat_fd), iostat_fd))

    pidstat_cmd = f"pidstat -p ALL {interval} -o JSON"
    pidstat_fd = open(os.path.join(SYSSTAT_DIRECTORY, "pidstat.json"), "w")
    PROCESSES.append((subprocess.Popen(shlex.split(pidstat_cmd), stdout=pidstat_fd), pidstat_fd))

    # But sar does not need a fd
    sar_cmd = f"sar -bdFqrSuWx -I SUM -n DEV -n EDEV -P ALL {interval} -o {SYSSTAT_DIRECTORY}/sar"
    PROCESSES.append((subprocess.Popen(shlex.split(sar_cmd)), None))

    def stop():
        stop_monitoring()

    if timeout:
        TIMER = threading.Timer(timeout, stop).start()


def stop_monitoring():
    """    
    Stop monitoring system usage with sysstat

    @return: nothing
    """
    global PROCESSES
    global TIMER
    
    # Reset timer
    TIMER = None

    # Use sadf as frontend to the sar 
    sarbin = f"{SYSSTAT_DIRECTORY}/sar"
    sadf_cmd = f"sadf -j {sarbin} -- -bdFqrSuWx -I SUM -n DEV -n EDEV -P ALL > {SYSSTAT_DIRECTORY}/sar.json"

    # Cleanup
    for process, fd in PROCESSES:
        # Stop the entire process with SIGINT first
        process.send_signal(signal.SIGINT)
        # Wait a little before killing the process
        time.sleep(1)
        try:
            # Wait max. 3 seconds before kiling the process
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        # Close the output file handle
        if fd:
            fd.close()

    PROCESSES.clear()

    if os.path.exists(sarbin):
        # Parse sar binary to json with sadf
        sadf_process = subprocess.run(sadf_cmd,shell=True)
        if sadf_process.returncode != 0:
            # Something went wrong
            raise Exception(sadf_process) 
    
        # Delete sar binary manually
        os.remove(sarbin)