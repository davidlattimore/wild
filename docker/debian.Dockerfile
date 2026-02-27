# Run on a recent version of Debian
#
# docker build --progress=plain -t wild-dev-debian . -f docker/debian.Dockerfile
# docker run -it wild-dev-debian

FROM rust:1.93 AS chef
RUN apt-get update && \
    apt-get install -y \
        clang \
        clang-format \
        lld \
        less \
        qemu-user \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        build-essential \
        && \
    rm -rf /var/lib/apt/lists/*
RUN ln -s `which ld.lld-16` /usr/local/bin/ld.lld
RUN cargo install --locked cargo-chef
RUN rustup toolchain install nightly && \
    rustup target add --toolchain nightly \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-gnu \
        aarch64-unknown-linux-musl \
        && \
    rustup component add rustc-codegen-cranelift-preview --toolchain nightly
WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
