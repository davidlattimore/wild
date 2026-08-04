FROM archlinux:base

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN pacman --noconfirm -Syu \        
        base-devel \
        clang \
        curl \
        git \
        lld \
        qemu-user \
        aarch64-linux-gnu-gcc \
        riscv64-linux-gnu-gcc \
        taplo-cli \
        wget
RUN pacman --noconfirm -Scc
RUN wget https://sh.rustup.rs -O rustup-installer && \
    chmod +x rustup-installer && \
    ./rustup-installer -y --default-toolchain 1.97.1
RUN rustup toolchain install nightly \
        --allow-downgrade \
        --target x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl,riscv64gc-unknown-linux-gnu,riscv64gc-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview
