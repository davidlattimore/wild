# Run on a recent version of Ubuntu
#
# docker build --progress=plain -t wild-dev-ubuntu . -f docker/ubuntu.Dockerfile
# docker run -it wild-dev-ubuntu

FROM ubuntu:25.04 AS chef
RUN apt-get update && \
    apt-get install -y \
        clang \
        lld \
        less \
        qemu-user \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        gcc-riscv64-linux-gnu \
        g++-riscv64-linux-gnu \
        binutils-riscv64-linux-gnu \
        build-essential \
        rustup \
        && \
    rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly && \
    rustup target add --toolchain nightly \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-gnu \
        aarch64-unknown-linux-musl \
        riscv64gc-unknown-linux-gnu \
        riscv64gc-unknown-linux-musl \
        && \
    rustup component add rustc-codegen-cranelift-preview --toolchain nightly
RUN cargo install --locked cargo-chef
WORKDIR /wild
