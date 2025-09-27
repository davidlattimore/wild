# Run on a recent version of Fedora
#
# docker build --progress=plain -t wild-dev-fedora . -f docker/fedora.Dockerfile
# docker run -it wild-dev-fedora

FROM fedora:44 AS chef
RUN dnf -y update && \
    dnf -y install \
        clang \
        llvm \
        lld \
        mold \
        gdb \
        valgrind \
        less \
        qemu-user \
        gcc-aarch64-linux-gnu \
        gcc-c++-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        gcc-riscv64-linux-gnu \
        gcc-c++-riscv64-linux-gnu \
        binutils-riscv64-linux-gnu \
        @development-tools \
        elfutils \
        rustup \
        vim \
    && dnf clean all
RUN rustup-init --default-toolchain stable -y
ENV PATH="/root/.cargo/bin:${PATH}"
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
