# Use debian for the docker image from dockerhub for all architecture
#FROM --platform=$BUILDPLATFORM debian:stable-backports
FROM debian:stable-backports

# Install apt dependencies
RUN apt update && apt install -y -t stable-backports iputils-ping python3 python3-pip suricata && apt clean

# Install python dependencies
RUN pip3 install --break-system-packages flask flask-restx gunicorn dpkt numpy tensorflow

# Set up suricata properly
# Also enable et/open dataset as default and add all relevant rulesets by abuse.ch
RUN suricata-update && suricata-update enable-source abuse.ch/sslbl-blacklist && suricata-update enable-source abuse.ch/sslbl-c2 && suricata-update enable-source abuse.ch/sslbl-ja3 && suricata-update update-sources

# Set up working directory
WORKDIR /app

# Copy the python and bash scripts
COPY flask_api.py /app/
COPY setup.py /app/
COPY states.py /app/
COPY start.sh /app/
COPY ml_analysis.py /app/
COPY ml_analysis_multiprocess.py /app/
COPY rb_analysis.py /app/
COPY aggregator.py /app/
COPY kisshome_ids.py /app/
COPY ip_to_country.csv /app/
COPY ip_to_asn.csv /app/

RUN chmod a+x /app/flask_api.py
RUN chmod a+x /app/setup.py
RUN chmod a+x /app/states.py
RUN chmod a+x /app/start.sh
RUN chmod a+x /app/ml_analysis.py
RUN chmod a+x /app/ml_analysis_multiprocess.py
RUN chmod a+x /app/rb_analysis.py
RUN chmod a+x /app/aggregator.py
RUN chmod a+x /app/kisshome_ids.py

# Copy suricata configuration and rules
COPY kisshome.rules /etc/suricata/rules/kisshome.rules
COPY suricata.yaml /etc/suricata/suricata.yaml

# Open port 5000 for the API
EXPOSE 5000

# Set the entry point
ENTRYPOINT ["/app/start.sh"]
