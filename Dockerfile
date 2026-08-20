# Pinned to bookworm so the builder's glibc matches the runtime image.
# `rust:1` alone now resolves to trixie (glibc 2.39) and the resulting
# binary dies on bookworm-slim (2.36) with `GLIBC_2.39 not found` — the
# same trap onym-relayer's image documents.
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --manifest-path operator/Cargo.toml

FROM debian:bookworm-slim
# ca-certificates for the revocation-epoch poll, which is the only
# outbound request this service ever makes. SQLite is compiled in via
# `rusqlite/bundled`, so there is no libsqlite3 to install.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/operator/target/release/onym-backup-operator /usr/local/bin/onym-backup-operator

# Unprivileged. This process holds other people's sealed archives and
# has no reason to be able to write anywhere but its own two
# directories; nothing it serves needs a privileged operation.
RUN useradd --system --uid 10001 --create-home --home-dir /var/lib/onym-backup operator \
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

EXPOSE 8080
CMD ["onym-backup-operator"]
