FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Note, we don't currently install rustup via apt-get, since the version in 26.04 is too old to work
# correctly with the rust-cache action, which requires `rustup toolchain list --quiet` to work
# (1.28.0 or later).

RUN apt-get update \
    && apt-get install -y eatmydata \
    && eatmydata apt-get -y install \
        build-essential \
        clang \
        clang-format \
        curl \
        dwarfdump \
        g++ \
        gcc \
        gdb \
        git \
        lld \
        llvm \
        perl \
        wget \
        xz-utils \
        zstd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-$(uname -m).gz \
        | gzip -d - | install -m 755 /dev/stdin /usr/local/bin/taplo \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path

