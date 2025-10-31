# Docker image with suricata for various architectures

Make sure docker is running on the target system. Use `docker-ce` and not `docker`. The install can look like this:

```bash
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ sudo sh get-docker.sh
```

## Build

To build the present docker image for `arm` and `x64`, first create a builder with `buildx`. Use

```bash
$ sudo docker buildx create --use --name multiarch_builder
```

To publish the build, run

```bash
$ sudo docker buildx build -f Dockerfile-base --platform linux/amd64,linux/arm64 -t dgrossenbach/ids:base --push .
$ sudo docker buildx build -f Dockerfile-stable --platform linux/amd64,linux/arm64 -t dgrossenbach/ids:stable --push .
```

To debug the output of docker it is recommended to use the `--progress=plain` flag.

## Pull

To pull an image, use

```bash
$ sudo docker pull kisshome/ids:stable
```

## Run

To run the build or pulled image with the exposed port and remove it afterward, use

```bash
$ sudo docker run --rm -d -p 5000:5000 -v kisshome/ids:stable
```

If a shared volume (like `/var/log/shared`) is provided, run

```bash
$ sudo mkdir -p /var/log/shared

$ sudo docker run --rm -d -p 5000:5000 --security-opt apparmor=unconfined -v /var/log/shared:/shared:Z kisshome/ids:stable
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
$ python3 /extras/test_api/demo_api.py
```