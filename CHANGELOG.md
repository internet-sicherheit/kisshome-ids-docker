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
