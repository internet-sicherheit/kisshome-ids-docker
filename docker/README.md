# Docker image with suricata for various architectures

Make sure docker is running on the target system. Use `docker-ce` and not `docker`. The install can look like this:

```bash
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ sudo sh get-docker.sh
```

## Config

Currently all pcaps are expected to be found in the `/data` directory on the target host.

First create the .json file in `/etc/docker/daemon.json` or `/.config/docker/daemon.json` (rootless) to enable multi platform builds by adding following lines:

```json
{
  "features": {
    "containerd-snapshotter": true
  }
}
```

After that restart the daemon:

```bash
$ sudo systemctl restart docker
```

## Build

### Buildx

To build the present docker image for `arm` and `x64`, first create a builder with `buildx`. Use

```bash
$ sudo docker buildx create --use --name multiarch_builder
```

To publish the build, run

```bash
$ sudo docker buildx build --platform linux/amd64,linux/arm64 -t dgrossenbach/ids:stable-backports --push .
```

### Containerd (Not recommended)

#### Config

Currently all pcaps are expected to be found in the `/data` directory on the target host.

First create the .json file in `/etc/docker/daemon.json` or `/.config/docker/daemon.json` (rootless) to enable multi platform builds by adding following lines:

```json
{
  "features": {
    "containerd-snapshotter": true
  }
}
```

After that restart the daemon:

```bash
$ sudo systemctl restart docker
```

#### Build

Since we build manually, we need to replace the first line in the `Dockerfile` by adding `--platform=$BUILDPLATFORM`:

```bash
FROM --platform=$BUILDPLATFORM debian:stable-backports
```

Then, to build the present docker image for `arm` and `x64`, use

```bash
$ sudo docker build --platform linux/amd64,linux/arm64 -t kisshome/ids:stable-backports .
```

To debug the output of docker it is recommended to use the `--progress=plain` flag. Also, publishing it might go wrong since it has no `manifest`.

## Pull

To pull an image, use

```bash
$ sudo docker pull kisshome/ids:stable-backports
```

## Run

To run the build or pulled image with the exposed port and remove it afterward, use

```bash
$ sudo docker run --rm -d -p 5000:5000 -v kisshome/ids:stable-backports
```

If a shared volume (like `/var/log/shared`) is provided, run

```bash
$ sudo docker run --rm -d -p 5000:5000 --security-opt apparmor=unconfined -v /var/log/shared:/shared:z kisshome/ids:stable-backports
```

`--security-opt apparmor=unconfined` as well as `:z` prevent Ubuntu/Debian or SELinux Systems from blocking access to the shared volume.
The volume and the port are customizable.

## API

### Web

The docker container opens port `5000` for any communication with the API. Call http://localhost:5000/ to use the RESTful API.

### CLI (Not recommended)

One can also use `curl` to communicate with the API. Example:

```bash
$ curl -X GET http://localhost:5000/status
```

Pcap Data can be sent to the Docker API to be analyzed by:

```bash
$ curl -X POST -H "Content-Type: application/octet-stream" --data-binary @/path/to/file.pcap http://localhost:5000/pcap?pcap_name=test
```

or

```bash
$ cat /path/to/file.pcap | curl -X POST -H "Content-Type: application/octet-stream" --data-binary @- http://localhost:5000/pcap?pcap_name=test
```

To read the full API doc, visit http://localhost:5000/

## Demo

To run a demo server, you can use the preinstalled `docker0` bridge to host an own, little API. Run

```bash
$ python3 demo_api.py
```

## Structure

![Structure](https://gitlab.internet-sicherheit.de/kisshome/kisshome/-/blob/main/demonstrator/docker/classdiagram_demonstrator.drawio.png)

## Performance Analysis

### Processing Times 

Tests done to compare prodedural ml (ml_analysis.py) and multi-processing (here with 3 worker processes and 1 reader process for 4 Core raspi):

#### Laptop (no GPU)

| Mode          | Test Case                    | Time (Seconds)   | Time per Packet           |
|---------------|------------------------------|------------------|---------------------------|
| **Procedural**| Simple PCAP (5MB)            | 16               | 0.00030 s/packet          |
|               | Big PCAP (55.5MB)            | 229              |                           |
|               | Simple PCAP 10s (7.3KB)      | 0.05             | 0.0004 s/packet           |
|               | Big PCAP 10s (104KB)         | 0.6              |                           |
| **Multi Process**| Simple PCAP (5MB)         | 7                | 0.00012 s/packet          |
|               | Big PCAP (55.5MB)            | 98               |                           |
|               | Simple PCAP 10s (7.3KB)      | 0.14             | 0.0014 - 0.00013 s/packet |
|               | Big PCAP 10s (104KB)         | 0.35             |                           |

#### Raspberry Pi 5

| Mode          | Test Case                    | Time (Seconds)   | Time per Packet           |
|---------------|------------------------------|------------------|---------------------------|
| **Procedural**| Simple PCAP (5MB)            | 34               | 0.00061 s/packet          |
|               | Big PCAP (55.5MB)            | 444.5            |                           |
|               | Simple PCAP 10s (7.3KB)      | 0.14             | 0.0013 - 0.0008 s/packet  |
|               | Big PCAP 10s (104KB)         | 1.12             |                           |
| **Multi Process**| Simple PCAP (5MB)         | 20               | 0.00032 s/packet          |
|               | Big PCAP (55.5MB)            | 214              |                           |
|               | Simple PCAP 10s (7.3KB)      | 0.15             | 0.0015 - 0.0005 s/packet  |
|               | Big PCAP 10s (104KB)         | 0.75             |                           |

In continued tests (i.e. sending pcaps 20 + times, with enough time in between each), random spikes in processing time could be noticed.

Further analysis necessary for complete workflow (i.e. from the moment a pcap is sent via curl until the docker can provide a result).

### Raspberry Pi Memory Usage

| Condition                    | Memory Usage (GB) |
|------------------------------|-------------------|
| Baseline (ioBroker + OS)     | 0.77              |
| Suricata Only                | 1.7               |
| Machine Learning + Suricata  | 2.3               |


## TODOs / Open Questions

- Starting / Restarting ML (and suricata?) processes during configure
  - ensure ml worker processes (multiprocessing) also exit 
- Unified Error Handling in API
- Aggregating Results
  - Is ML always done faster than suricata? (i.e. can we assume if ml is done => suricata is done?)
  - results should only be for the current pcap, not previous
  - how do we return them? 
    - actively send them back: need to know when the script results are there (async await for results? / scripts notifying the aggregator?)
    - polling/longpolling: is this efficient? (we might receive constant polling requests or still need to await for results)
- /pcapstream only sends the 200 reponse once ml script is done reading in the pcap data, do we want it like this? (if there is an error during this in ml script the response is still 200 anyway)
- do performance analysis of whole process (from sending pcap until result received / ready for new pcap)
- tensorflow lite for ml inference? Depends on if we do training and whether training is in same script
