FROM opensuse/tumbleweed:latest

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN zypper refresh \
    && zypper in -y gcc gcc-c++ glibc-devel-static clang lld curl rustup \
    && zypper clean --all \
    && curl -fsSL https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-$(uname -m).gz \
        | gzip -d - | install -m 755 /dev/stdin /usr/local/bin/taplo \
    && rustup toolchain install nightly \
        --allow-downgrade \
        --target $(uname -m)-unknown-linux-musl \
        --component rustc-codegen-cranelift-preview
