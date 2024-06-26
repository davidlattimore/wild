# Provides a somewhat reproducible environment for running tests in.
# docker build -t wild-dev .
# docker run -it wild-dev

FROM rust:1.79 AS chef
RUN apt-get update && \
    apt-get install -y clang lld-16 less && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-chef
RUN rustup toolchain install nightly && \
    rustup target add x86_64-unknown-linux-musl && \
    rustup target add x86_64-unknown-linux-musl --toolchain nightly && \
    rustup component add rustc-codegen-cranelift-preview --toolchain nightly
WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
