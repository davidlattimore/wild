# Run on Ubuntu 24.04. We can't just apt install rustup here, so this is a bit different to later
# versions of ubuntu.

# docker build --progress=plain -t wild-dev-ubuntu-24-04 . -f docker/ubuntu-24.04.Dockerfile
# docker run -it wild-dev-ubuntu-24-04

FROM ubuntu:24.04 AS chef
RUN apt-get update && \
    apt-get install -y \
        clang \
        clang-format \
        llvm \
        lld \
        mold \
        gdb \
        valgrind \
        less \
        qemu-user \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        gcc-riscv64-linux-gnu \
        g++-riscv64-linux-gnu \
        binutils-riscv64-linux-gnu \
        build-essential \
        elfutils \
        vim \
        wget \
        && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://sh.rustup.rs -O rustup-installer && \
    chmod +x rustup-installer && \
    ./rustup-installer -y --default-toolchain 1.93.0

ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup toolchain install nightly \
        --allow-downgrade \
        --target x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl,riscv64gc-unknown-linux-gnu,riscv64gc-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview

RUN cargo install --locked cargo-chef
WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
