# Run on a recent version of alpine Linux
#
# docker build --progress=plain -t wild-dev-alpine . -f docker/alpine.Dockerfile
# docker run -it wild-dev-alpine

FROM rust:1.93-alpine AS chef
RUN wget -qO- https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.70/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xzf- && \
    mv cargo-chef /usr/local/bin
RUN rustup toolchain install nightly && \
    rustup component add rustc-codegen-cranelift-preview --toolchain nightly

RUN apk add build-base lld clang clang-extra-tools bash

WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
