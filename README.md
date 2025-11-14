# KISSHome IDS

Make sure docker is running on the target system. Use `docker-ce` and not `docker`. The install can look like this:

```bash
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ sudo sh get-docker.sh
```

## Run using the KISSHome Watchdog Skript

The easiest way to install and run is the 'install-kisshome-ids-watchdog.sh' Skript in the [KISSHome-IDS-Watchdog](https://github.com/internet-sicherheit/kisshome-ids-docker/tree/main/KISSHome-IDS-Watchdog) Folder

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

`--security-opt apparmor=unconfined` as well as `:Z` prevent Ubuntu/Debian or SELinux Systems from blocking access to the shared volume.
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

## License

MIT License

Copyright (c) 2025 if(is)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
