# Stage 1: Build C++ executable with vcpkg
FROM zeek/zeek:8.0 AS builder

RUN apt update -y && apt install -y \
    build-essential cmake git curl zip unzip tar pkg-config

RUN git clone https://github.com/microsoft/vcpkg /opt/vcpkg && \
    /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics
ENV VCPKG_ROOT=/opt/vcpkg

COPY CMakeLists.txt vcpkg.json /opt/src/
COPY src /opt/src/src
COPY tests /opt/src/tests

WORKDIR /opt/src
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j"$(nproc)"

# Stage 2: Final runtime image
FROM zeek/zeek:8.0

# Combine package installation, builds, and cleanup in a single RUN
# This ensures build tools like cmake and gcc don't bloat the final layer size
RUN apt update -y && apt upgrade -y && apt install -y \
    build-essential \
    cmake \
    curl \
    librdkafka-dev \
    libssl-dev \
    libpcap-dev \
    vim \
    pkg-config \
    iproute2 \
    && curl -fsSL https://github.com/edenhill/librdkafka/archive/refs/tags/v1.4.4.tar.gz -o /tmp/librdkafka.tar.gz \
    && tar -xzf /tmp/librdkafka.tar.gz -C /tmp \
    && cd /tmp/librdkafka-1.4.4 \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && yes | zkg install seisollc/zeek-kafka --version v1.2.0 --user-var LIBRDKAFKA_ROOT=/usr/local \
    && setcap cap_net_raw,cap_net_admin=+eip $(which zeek) \
    && apt-get remove --purge -y build-essential cmake curl pkg-config \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* ~/.zkg

# Copy only the compiled binary and essential zeek configs from the builder stage
COPY --from=builder /opt/src/build/hamstring_zeek /opt/hamstring_zeek
COPY --from=builder /opt/src/src/zeek/additional_configs /opt/src/zeek/additional_configs
COPY --from=builder /opt/src/src/zeek/base_node.cfg /opt/src/zeek/base_node.cfg

RUN mkdir /opt/logs
WORKDIR /opt/logs

RUN mkdir -p "/opt/static_files"
ENV STATIC_FILES_DIR="/opt/static_files"

CMD ["bash", "-c", "cd /opt/ && /opt/hamstring_zeek -c /opt/config.yaml"]
