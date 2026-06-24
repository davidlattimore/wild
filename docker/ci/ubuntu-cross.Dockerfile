ARG BASE_IMAGE=ghcr.io/wild-linker/wild/ci-ubuntu-amd64:latest
FROM ${BASE_IMAGE}

RUN eatmydata apt-get update \
    && eatmydata apt-get -y install \
        binutils-aarch64-linux-gnu \
        binutils-loongarch64-linux-gnu \
        binutils-powerpc64le-linux-gnu \
        binutils-riscv64-linux-gnu \
        g++-aarch64-linux-gnu \
        g++-loongarch64-linux-gnu \
        g++-powerpc64le-linux-gnu \
        g++-riscv64-linux-gnu \
        gcc-aarch64-linux-gnu \
        gcc-loongarch64-linux-gnu \
        gcc-powerpc64le-linux-gnu \
        gcc-riscv64-linux-gnu \
        qemu-user \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN eatmydata rustup toolchain install nightly \
        --allow-downgrade \
        --target x86_64-unknown-linux-gnu,x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl,riscv64gc-unknown-linux-gnu,riscv64gc-unknown-linux-musl,loongarch64-unknown-linux-gnu,loongarch64-unknown-linux-musl,powerpc64le-unknown-linux-gnu \
        --component rustc-codegen-cranelift-preview
