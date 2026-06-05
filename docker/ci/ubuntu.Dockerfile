ARG BASE_IMAGE=ghcr.io/wild-linker/wild/ci-ubuntu-amd64:latest
FROM ${BASE_IMAGE}

RUN eatmydata rustup toolchain install nightly \
        --allow-downgrade \
        --target $(uname -m)-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview
