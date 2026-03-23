FROM zeek/zeek:8.0

RUN apt update -y && apt upgrade -y && apt install -y \
    build-essential \
    cmake \
    git \
    curl \
    # Needed for vcpkg
    zip unzip tar \
    librdkafka-dev \
    libssl-dev \
    libpcap-dev \
    vim \
    pkg-config \
    iproute2

# vcpkg
RUN git clone https://github.com/microsoft/vcpkg /opt/vcpkg && \
    /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics
ENV VCPKG_ROOT=/opt/vcpkg

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

COPY CMakeLists.txt vcpkg.json /opt/src/
COPY src /opt/src/src
COPY tests /opt/src/tests

# Build C++
WORKDIR /opt/src
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build -j"$(nproc)"

RUN chown -R root:root /usr/local/zeek
RUN mkdir /opt/logs
WORKDIR /opt/logs

RUN mkdir -p "/opt/static_files"
ENV STATIC_FILES_DIR="/opt/static_files"

CMD ["bash", "-c", "cd /opt/ && /opt/src/build/hamstring_zeek -c /opt/config.yaml"]
