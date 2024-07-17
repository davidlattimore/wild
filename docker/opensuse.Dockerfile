# Runs on openSUSE
#
# docker build -t wild-dev-opensuse . -f docker/opensuse.Dockerfile
# docker run -it wild-dev-opensuse

FROM opensuse/leap:latest AS chef
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN zypper install -y -t pattern devel_C_C++ && zypper install -y lld17 vim less
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
