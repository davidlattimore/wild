# Run on Arch Linux with no rustup.
#
# docker build --progress=plain -t wild-dev-arch-basic . -f docker/arch-basic.Dockerfile
#
# docker run -it wild-dev-arch-basic

FROM archlinux:base-20250302.0.316047 AS chef

RUN pacman --noconfirm -Syu \
    wget \
    less \
    gcc \
    clang \
    lld \
    rust

RUN wget -qO- https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.71/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xzf- && \
    mv cargo-chef /usr/local/bin

WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
