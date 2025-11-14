# Changelog

## 1.5.1 (31-10-2025)

First stable version released for study

## 1.5.2 (03-11-2025)

### Changes

* Remove old command socket when starting suricata daemon
* Prevent race condition in aggregator when stoping monitoring manually vs. stopping via thread by increasing sleep to 15 seconds
* Add state checks in API
* Replaced key in Endpoint /status for reporting error log from "base64_gzip_logs" to the current version

## 1.5.3 (04-11-2025)

### Changes

* Fixed a bug causing an infinite loop in ml when an empty pcap was sent / no valid packets were sent
* Aggregator now reports (those) errors in the "results" parameter of the json response
* Fixed a bug caused by casting float64 to int8
* Fixed a bug when caused by dividing with 0 in a log message
* Resolved a possible race condition when monitoring with a thread by increasing sleep to 15 seconds (from 10)
* Fixed a bug in monitor.py to display the full cmd of the process using pidstat by using the -l flag 

## 1.5.4 (05-11-2025)

### Changes

* Handle Suricata daemon start more gracefully by testing the command socket 5 times before raising an error

## 1.5.5 (05-11-2025)

### Changes

* Change error report by sending only the last 5000 lines of each current used logfile instead of the whole content

## 1.5.6 (06-11-2025)

### Changes

* Fix blacklisting in suricata to prevent false Malware detections like `ET P2P Vuze BT UDP Connection`

## 1.5.7 (06-11-2025)

### Changes

* Make Suricata daemon start even more graceful by allowing 10 retries
* Use time.sleep(1) to give the socket more time to process the requests
* Rework ERROR state: ml and rb remove the ability to set it themselves, instead only the aggregator decides when the state is set
* Allow 3 written errors either from ml or rb before setting IDS into error state

## 1.5.8 (07-11-2025)

### Changes

* Fixed a bug with dpkt closing the pipe leading to an error in the API (reader close on fifo pipe)
* Switch state gracefully in aggregator
* Remove long sleep of 3 seconds in ml

## 1.5.9 (08-11-2025)

### Changes

* Increased sleep in API from 1 to 3 seconds in /pcap
* Add more sleeps to suricata in order to prevent overloading of the command socket

## 1.6.0 (09-11-2025)

### Changes

* Remove pcap-current command since it seems to cause trouble
* Now check log file to determine if suricata has finished

## 1.6.1 (11-11-2025)

### Changes

* Change literal_eval to json.loads in aggegator
* Revert retry attempts from 10 to 3 in rb_analysis 

## 1.6.2 (11-11-2025)

### Changes

* Remove state "Configuring" because of potential race condition

## 1.6.3 (13-11-2025)

### Changes

* Reset error count on succesful result send

