# Runs on openSUSE
#
# docker build --progress=plain -t wild-dev-opensuse . -f docker/opensuse.Dockerfile
# docker run -it wild-dev-opensuse

FROM opensuse/tumbleweed@sha256:56df080fe1129ac6f15a59dd7c9a3ae27bd1f4719e2cfc0e8890afd090c677c9 AS chef
RUN zypper install -y -t pattern devel_C_C++ && \
    zypper install -y \
        rustup \
        clang \
        glibc-devel-static \
        cross-aarch64-gcc14 \
        cross-aarch64-binutils \
        cross-riscv64-gcc14 \
        cross-riscv64-binutils \
        qemu-linux-user \
        lld \
        vim \
        less
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

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
