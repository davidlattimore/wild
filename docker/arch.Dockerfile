# Run on Arch Linux. Includes some useful tools for debugging linker problems. In particular,
# includes rr - the replay debugger.
#
# docker build --progress=plain -t wild-dev-arch . -f docker/arch.Dockerfile
#
# docker run -it wild-dev-arch
#
# To actually use rr, you'll need to run with
# `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`
# See https://github.com/rr-debugger/rr/wiki/Docker

FROM archlinux:base-20251005.0.430597 AS chef

RUN pacman --noconfirm -Syu \
    wget \
    less \
    gcc \
    clang \
    lld \
    aarch64-linux-gnu-gcc \
    riscv64-linux-gnu-gcc \
    qemu-user \
    git \
    base-devel \
    perf \
    capnproto \
    cmake \
    gdb \
    ninja

# Install rr
RUN useradd --no-create-home --shell=/bin/false build && usermod -L build && \
    echo -e "build ALL=(ALL) NOPASSWD: ALL\nroot ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    mkdir /build && \
    chown build /build
USER build
RUN cd /build && \
    git clone https://aur.archlinux.org/rr.git && \
    cd /build/rr && \
    makepkg
USER root
RUN pacman --noconfirm -U /build/rr/rr-*.tar.zst

RUN wget -qO- https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.71/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xzf- && \
    mv cargo-chef /usr/local/bin

RUN wget https://sh.rustup.rs -O rustup-installer && \
    chmod +x rustup-installer && \
    ./rustup-installer -y --default-toolchain 1.93.0

ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup toolchain install nightly \
        --allow-downgrade \
        --target x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl,riscv64gc-unknown-linux-gnu,riscv64gc-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview

WORKDIR /wild

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY . .
