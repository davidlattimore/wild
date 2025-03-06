# Run on Arch Linux
#
# docker build --progress=plain -t wild-dev-arch . -f docker/arch.Dockerfile
# docker run -it wild-dev-arch

FROM archlinux:base-20250302.0.316047 AS chef

RUN pacman --noconfirm -Syu wget less gcc clang lld aarch64-linux-gnu-gcc qemu-user

RUN wget -qO- https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.71/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xzf- && \
    mv cargo-chef /usr/local/bin

RUN wget https://sh.rustup.rs -O rustup-installer && \
    chmod +x rustup-installer && \
    ./rustup-installer -y

ENV PATH="/root/.cargo/bin:$PATH"

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
