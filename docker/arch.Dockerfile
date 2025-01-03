# Run on Arch Linux
#
# docker build --progress=plain -t wild-dev-arch . -f docker/arch.Dockerfile
# docker run -it wild-dev-arch

FROM archlinux:base-20241222.0.291122 AS chef

RUN pacman --noconfirm -Syu wget less gcc clang lld

RUN wget -qO- https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.68/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xzf- && \
    mv cargo-chef /usr/local/bin

RUN wget https://sh.rustup.rs -O rustup-installer && \
    chmod +x rustup-installer && \
    ./rustup-installer -y

ENV PATH="/root/.cargo/bin:$PATH"

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
