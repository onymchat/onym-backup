# Pinned to bookworm so the builder's glibc matches the runtime image.
# `rust:1` alone now resolves to trixie (glibc 2.39) and the resulting
# binary dies on bookworm-slim (2.36) with `GLIBC_2.39 not found` — the
# same trap onym-relayer's image documents.
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked --manifest-path operator/Cargo.toml

FROM debian:bookworm-slim
# **No packages, and no CA bundle.** Worth stating, because the obvious
# reading of an outbound HTTPS client is that it needs one.
#
# `reqwest` is declared with `rustls-tls` and no default features, which
# resolves to `webpki-roots` — a root store compiled into the binary.
# It never reads /etc/ssl/certs, so `ca-certificates` would be an
# unused package justified by a comment that sounds right.
#
# The tradeoff is real and belongs to the dependency, not the image: a
# compiled-in root store is updated by rebuilding rather than by the
# distribution. Switching to `rustls-tls-native-roots` would move that
# decision to the OS — and would make `ca-certificates` genuinely
# required here, so the two changes go together or neither does.
COPY --from=builder /build/operator/target/release/onym-backup-operator /usr/local/bin/onym-backup-operator

# Unprivileged. This process holds other people's sealed archives and
# has no reason to be able to write anywhere but its own two
# directories; nothing it serves needs a privileged operation.
# No home directory: the process writes to /data and /blobs and nowhere
# else, so creating one would be inventing a third writable path for
# nothing to use.
RUN useradd --system --uid 10001 --no-create-home --home-dir /nonexistent operator \
    && mkdir -p /data /blobs \
    && chown operator:operator /data /blobs
USER operator

# Bookkeeping and bytes are separated deliberately. The SQLite store is
# small and can live on whatever disk the container is given; `/blobs`
# holds sealed snapshots measured in gigabytes and is expected to be a
# real mount. An operator that leaves it on the root filesystem will
# eventually fill that filesystem, and everything sharing the box fails
# with it — which is a worse outcome than backup being unavailable.
VOLUME ["/data", "/blobs"]
ENV BACKUP_STORE_PATH=/data/backup.sqlite \
    BACKUP_BLOB_ROOT=/blobs

# No HEALTHCHECK, matching the other services in the onym-infra stack.
# The operator serves /health, but a healthcheck needs a client inside
# the image, and adding curl to a distroless-ish runtime to poll a
# service Caddy is already proxying buys a status column at the cost of
# more surface in the container that holds the sealed archives.
EXPOSE 8080
CMD ["onym-backup-operator"]
