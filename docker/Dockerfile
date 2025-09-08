# Use debian for the docker image from dockerhub for all architecture
#FROM --platform=$BUILDPLATFORM debian:stable
FROM debian:stable

# Install apt dependencies
RUN apt update && apt install -y python3 python3-pip suricata && apt clean

# Install python dependencies
RUN pip3 install --break-system-packages flask flask-restx gunicorn schedule filelock dpkt numpy tensorflow

# Set up suricata properly
# Also enable et/open dataset as default and add all relevant rulesets by abuse.ch (currently only URLhaus is maintained)
#RUN suricata-update && suricata-update enable-source abuse.ch/sslbl-blacklist && suricata-update enable-source abuse.ch/sslbl-c2 && suricata-update enable-source abuse.ch/sslbl-ja3 && suricata-update update-sources
RUN suricata-update && suricata-update enable-source abuse.ch/urlhaus && suricata-update update-sources

# Copy suricata rules to the default rule path in the yaml
COPY kisshome.rules /var/lib/suricata/rules/

# Set up working directories
# First directory is for the shared volume mounted on the host, used later
WORKDIR /shared

# Second directory is for pipes, used later
WORKDIR /pipe

# Third directory is for the configuration
WORKDIR /config

# Copy suricata yaml file to not the default generated yaml file
COPY suricata.yaml /config/

# Copy csv files
COPY ip_to_country.csv /config/
COPY ip_to_asn.csv /config/

# Last directory is for the application
WORKDIR /app

# Copy the python and bash scripts
COPY start.sh /app/
COPY flask_api.py /app/
COPY setup.py /app/
COPY states.py /app/
COPY ml_analysis_multiprocess.py /app/
COPY rb_analysis.py /app/
COPY aggregator.py /app/
COPY kisshome_ids.py /app/

RUN chmod a+x /app/start.sh
RUN chmod a+x /app/flask_api.py
RUN chmod a+x /app/setup.py
RUN chmod a+x /app/states.py
RUN chmod a+x /app/ml_analysis_multiprocess.py
RUN chmod a+x /app/rb_analysis.py
RUN chmod a+x /app/aggregator.py
RUN chmod a+x /app/kisshome_ids.py

# Open port 5000 for the API
EXPOSE 5000

# Set the entry point
ENTRYPOINT ["/app/start.sh"]
