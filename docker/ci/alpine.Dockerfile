FROM rust:1.94-alpine

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apk add --no-cache build-base lld clang clang-extra-tools bash curl tar \
    && curl -fsSL https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-$(uname -m).gz \
        | gzip -d - | install -m 755 /dev/stdin /usr/local/bin/taplo \
    && rustup toolchain install nightly \
        --allow-downgrade \
        --target $(uname -m)-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview
