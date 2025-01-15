# Runs on openSUSE
#
# docker build --progress=plain -t wild-dev-opensuse . -f docker/opensuse.Dockerfile
# docker run -it wild-dev-opensuse

FROM opensuse/tumbleweed@sha256:a8b3f189cb0a1379c618b4fa581003f9551486d98fc21a1df559f7172f87c626 AS chef
RUN zypper install -y -t pattern devel_C_C++ && \
    zypper install -y \
        rustup \
        clang \
        glibc-devel-static \
        lld \
        vim \
        less
RUN rustup toolchain install nightly
RUN cargo install --locked cargo-chef
RUN rustup target add x86_64-unknown-linux-musl && \
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
