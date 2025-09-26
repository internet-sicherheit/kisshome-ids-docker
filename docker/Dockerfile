# Use debian for the docker image from dockerhub for all architectures
#
# Multistage: First build binaries and copy to real image later
# Building Suricata causes much overhead, so build latest version of Suricata 7
# Stage 1 (suricata-builder, use full image)
FROM debian:stable AS suricata-builder

# Use a temporary location to build suricata binaries
ARG INSTALL_LOCATION=/fakeroot

# Set the temporary location
ENV PREFIX=${INSTALL_LOCATION}

# Install apt dependencies
RUN apt update && \
    apt install -y \
    build-essential \
    libpcre2-dev \
    libyaml-dev \
    libjansson-dev \
    libmagic-dev \
    libpcap-dev \
    libnet1-dev \
    libcap-ng-dev \
    liblua5.3-dev \
    libgeoip-dev \
    libhiredis-dev \
    pkg-config \
    autoconf \
    automake \
    libtool \
    git \
    wget \
    make \
    xz-utils \
    python3-dev \
    python3-yaml \
    pciutils \
    rustc \
    cargo \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# Define Suricata version
ARG SURICATA_VERSION=7.0.12

# Download and build with static libraries and without hardware optimization
RUN wget \
    https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz \
    && tar -xvzf suricata-${SURICATA_VERSION}.tar.gz \
    && cd suricata-${SURICATA_VERSION} \
    && ./configure --disable-shared --disable-gccmarch-native --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    && make -j$(nproc) \
    && make install install-conf DESTDIR=${INSTALL_LOCATION} \
    && cd .. \
    && rm -rf suricata-${SURICATA_VERSION}*

# Stage 2 (final, use slim)
FROM debian:stable-slim AS final

# Install apt dependencies
RUN apt update && \
    apt install -y \
    wget \
    libpcre2-8-0 \
    libyaml-0-2 \
    libjansson4 \
    libmagic1 \
    libpcap0.8 \
    libnet1 \
    libcap-ng0 \
    liblua5.3-0 \
    libgeoip1 \
    libhiredis1.1.0 \
    python3 \
    python3-pip \
    pciutils \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# Set sysstat version
ARG SYSSTAT_VERSION=12.7.8

# Download, build, install, and clean up
# Cannot move to builder stage because of static file linking inside the sar binary
# But it is not crucial since only wget needs to be installed for the image version (minimal overhead)
RUN wget https://github.com/sysstat/sysstat/archive/refs/tags/v${SYSSTAT_VERSION}.tar.gz && \
    tar -xzf v${SYSSTAT_VERSION}.tar.gz && \
    cd sysstat-${SYSSTAT_VERSION} && \
    ./configure --prefix=/usr && \
    make && \
    make install && \
    cd .. && \
    rm -rf sysstat-${SYSSTAT_VERSION}*

# Install python dependencies for "normal" packages
RUN pip3 install --break-system-packages \
    PyYAML \
    setproctitle \
    filelock \
    schedule \
    flask \
    flask-restx \
    gunicorn \
    dpkt \
    numpy

# Install python dependencies for tensorflow
RUN pip3 install --break-system-packages tensorflow

# Install python dependencies for pytorch 
#RUN pip3 install --break-system-packages torch torchvision --index-url https://download.pytorch.org/whl/cpu

# Copy Suricata binaries and support files
COPY --from=suricata-builder /fakeroot/usr/bin/suricata* /usr/bin/
COPY --from=suricata-builder /fakeroot/usr/lib/suricata /usr/lib/suricata
COPY --from=suricata-builder /fakeroot/etc/suricata /etc/suricata
COPY --from=suricata-builder /fakeroot/var/log/suricata /var/log/suricata
COPY --from=suricata-builder /fakeroot/var/lib/suricata /var/lib/suricata
COPY --from=suricata-builder /fakeroot/var/run/suricata /var/run/suricata

# Set up suricata properly
# Also enable et/open dataset as default and add all relevant rulesets by abuse.ch (currently only URLhaus is maintained)
#RUN suricata-update && suricata-update enable-source abuse.ch/sslbl-blacklist && suricata-update enable-source abuse.ch/sslbl-c2 && suricata-update enable-source abuse.ch/sslbl-ja3 && suricata-update update-sources
RUN suricata-update update-sources && suricata-update enable-source abuse.ch/urlhaus && suricata-update --no-test --no-reload

# Copy suricata rules to the default rule path in the yaml
COPY kisshome.rules /var/lib/suricata/rules/

# Set up working directories
# First directory is for the shared volume mounted on the host, used later
WORKDIR /shared

# Second directory is for pipes, used later
WORKDIR /pipe

# Third directory is for the configuration
WORKDIR /config

# Fourth directory is for the stat collection
WORKDIR /stat,

# Copy suricata yaml file to not use the default generated yaml file
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
COPY monitor.py /app/
COPY ml_analysis_multiprocess.py /app/
COPY rb_analysis.py /app/
COPY aggregator.py /app/
COPY kisshome_ids.py /app/

RUN chmod a+x /app/start.sh
RUN chmod a+x /app/flask_api.py
RUN chmod a+x /app/setup.py
RUN chmod a+x /app/states.py
RUN chmod a+x /app/monitor.py
RUN chmod a+x /app/ml_analysis_multiprocess.py
RUN chmod a+x /app/rb_analysis.py
RUN chmod a+x /app/aggregator.py
RUN chmod a+x /app/kisshome_ids.py

# Open port 5000 for the API
EXPOSE 5000

# Set the entry point
ENTRYPOINT ["/app/start.sh"]
