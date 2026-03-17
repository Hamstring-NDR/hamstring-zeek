FROM zeek/zeek:8.0

RUN apt update -y && apt upgrade -y
RUN apt install -y \
    build-essential \
    cmake \
    curl \
    librdkafka-dev \
    libssl-dev \
    libpcap-dev \
    vim \
    pkg-config \
    iproute2 \
    python3-pip

# download and install librdafka v1.4.4
RUN curl -fsSL https://github.com/edenhill/librdkafka/archive/refs/tags/v1.4.4.tar.gz -o /tmp/librdkafka.tar.gz \
    && tar -xzf /tmp/librdkafka.tar.gz -C /tmp \
    && cd /tmp/librdkafka-1.4.4 \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/librdkafka-1.4.4 /tmp/librdkafka.tar.gz

# install the zeek kafka plugin
RUN yes | zkg install seisollc/zeek-kafka --version v1.2.0 --user-var LIBRDKAFKA_ROOT=/usr/local
RUN setcap cap_net_raw,cap_net_admin=+eip $(which zeek)

RUN rm /usr/lib/python3.13/EXTERNALLY-MANAGED
COPY requirements/requirements.zeek.txt /opt/requirements.txt
RUN pip3 install -r /opt/requirements.txt

COPY ./src /opt/src

RUN chown -R root:root /usr/local/zeek
RUN mkdir /opt/logs
WORKDIR /opt/logs


RUN mkdir "/opt/static_files"
ENV STATIC_FILES_DIR="/opt/static_files"

CMD ["bash", "-c", "cd /opt/ && python3 /opt/src/zeek/zeek_handler.py -c /opt/config.yaml"]
