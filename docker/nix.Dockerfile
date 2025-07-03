# Run inside a Nix shell.
#
# docker build --progress=plain -t wild-dev-nix . -f docker/nix.Dockerfile
#
# docker run -it wild-dev-nix

FROM nixos/nix AS chef

COPY docker/shell.nix shell.nix
RUN nix-shell --run "rustup toolchain install nightly"

WORKDIR /wild

FROM chef AS planner
COPY . .
RUN nix-shell --run "cargo chef prepare --recipe-path recipe.json"

FROM chef AS builder
COPY --from=planner /wild/recipe.json recipe.json
COPY docker/shell.nix shell.nix
RUN nix-shell --run "cargo chef cook --all-targets --recipe-path recipe.json"
COPY . .

ENTRYPOINT ["nix-shell"]
