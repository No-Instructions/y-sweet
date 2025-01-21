FROM rust:1.83-slim-bookworm AS builder

WORKDIR /build

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

ENV YSWEET_STORE="s3"

COPY --from=builder /build/target/release/y-sweet /usr/local/bin/y-sweet

CMD ["y-sweet", "serve", "--host=0.0.0.0", "--prod"]
