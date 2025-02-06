FROM rust:1.83-slim-bookworm AS builder

WORKDIR /build

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

# Write to disk by default
ENV YSWEET_STORE="data"

# Add y-sweet binary
COPY --from=builder /build/target/release/y-sweet /usr/local/bin/y-sweet

# Add tailscale
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscale /usr/local/bin/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale

# Entrypoint wrapper
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve", "--host=0.0.0.0", "--prod"]
