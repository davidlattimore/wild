ARG BASE_IMAGE=ghcr.io/wild-linker/wild/ci-ubuntu-base-amd64:latest
FROM ${BASE_IMAGE}

RUN eatmydata apt-get update \
    && eatmydata apt-get -y install \
        gcc-multilib \
        wabt \
        wasi-libc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN eatmydata rustup target add wasm32-wasip1
