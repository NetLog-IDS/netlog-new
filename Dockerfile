# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    git \
    ccache \
    libpcap-dev \
    libssl-dev \
    zlib1g-dev \
    libsasl2-dev \ 
    python3.10 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the project
RUN rm -rf build && \
    mkdir -p build && \
    cd build && \
    cmake .. \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DSPOOFY_BUILD_TESTS=0 \
        -DSPOOFY_FETCH_DEPS=1 \
        -DRDKAFKA_BUILD_STATIC=1 \
        -DRDKAFKA_BUILD_TESTS=OFF \
        -DRAPIDJSON_BUILD_TESTS=OFF \
        -DRAPIDJSON_BUILD_EXAMPLES=OFF \
        -DLIBTINS_BUILD_TESTS=0 \
        -DLIBTINS_BUILD_SHARED=0 \
        -DCMAKE_BUILD_TYPE=Debug && \
    cmake --build . --parallel $(nproc)

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcap0.8 \
    libssl3 \
    zlib1g \
    libsasl2-2 && \
    rm -rf /var/lib/apt/lists/*

# Copy the built executable
COPY --from=builder /app/build/bin/spoofy /usr/local/bin/spoofy

COPY wait-for-it.sh .

# COPY --from=builder /app/*.pcap .

COPY --from=builder /app/*.pcapng .

# ENTRYPOINT ["/usr/local/bin/spoofy", "-i", "test.pcapng", "-f", "tcp or udp", "--sender", "kafka", "--broker", "kafka:9092", "--topic", "network-traffic"]
ENTRYPOINT ["/usr/local/bin/spoofy", "-i", "friday_test.pcap", "-f", "tcp or udp", "--sender", "kafka", "--broker", "localhost:19092", "--topic", "network-traffic", "--replay"]

# Add capabilities for raw network access (optional)
# RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/spoofy
