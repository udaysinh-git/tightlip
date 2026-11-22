FROM node:22.23.5-trixie-slim@sha256:68c76cfad89921b927eae28ba21407475e29d0ce450afcdbe70c1532db042b64 AS node

FROM rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS builder

ENV CARGO_BUILD_JOBS=2
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm/ /usr/local/lib/node_modules/npm/
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && rustup target add wasm32-unknown-unknown

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo install --locked --version 0.2.130 wasm-bindgen-cli

WORKDIR /src
COPY . .

WORKDIR /src/web
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    npm ci && npm run build

WORKDIR /src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p tightlip-server \
    && install -D -m 0755 target/release/tightlip /out/tightlip \
    && install -d -m 0700 /out/rootfs/data

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS runtime

WORKDIR /app
COPY --from=builder /out/tightlip /app/tightlip
COPY --from=builder /src/web/dist/ /app/web/
COPY --from=builder --chown=65532:65532 /out/rootfs/ /

USER 65532:65532
ENV TIGHTLIP_WEB_DIR=/app/web TIGHTLIP_DATA_DIR=/data PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/tightlip", "--healthcheck"]
ENTRYPOINT ["/app/tightlip"]
