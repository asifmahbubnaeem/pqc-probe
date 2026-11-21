# syntax=docker/dockerfile:1
#
# pqc-probe: the CLI and the web service, with two client stacks side by side.
#
#   stock         Debian's own openssl (3.5) and ssh (OpenSSH 10.0)
#   experimental  the same openssl with oqs-provider loaded, and the OQS-OpenSSH client
#
# Build:  docker build -t pqc-probe .
# Run:    see docs/docker.md
#
# Versions are build arguments. The image records what it was built from in
# /opt/pqc-probe/VERSIONS, including the exact OQS-OpenSSH commit.

ARG DEBIAN=trixie
ARG RUST_IMAGE=rust:1-slim-trixie

# ---------------------------------------------------------------------------------------------
# 1. pqc-probe binaries
# ---------------------------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p pqc-probe -p pqc-probe-web \
 && install -D -m 0755 target/release/pqc-probe /out/pqc-probe \
 && install -D -m 0755 target/release/pqc-probe-web /out/pqc-probe-web

# ---------------------------------------------------------------------------------------------
# 2. Experimental TLS: liboqs + oqs-provider, built against Debian's OpenSSL 3.5.
#    oqs-provider 0.11.0 is the release upstream states is in sync with liboqs 0.15.0.
# ---------------------------------------------------------------------------------------------
FROM debian:${DEBIAN}-slim AS oqs-provider
ARG LIBOQS_VERSION=0.15.0
ARG OQS_PROVIDER_VERSION=0.11.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential cmake ninja-build libssl-dev \
 && rm -rf /var/lib/apt/lists/*
# OQS_DIST_BUILD: pick CPU features at run time, so the image works on machines other than the
# one that built it.
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git /src/liboqs \
 && cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
 && cmake --build /src/liboqs/build \
 && cmake --install /src/liboqs/build
RUN git clone --depth 1 --branch "${OQS_PROVIDER_VERSION}" https://github.com/open-quantum-safe/oqs-provider.git /src/oqs-provider \
 && cmake -S /src/oqs-provider -B /src/oqs-provider/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs \
 && cmake --build /src/oqs-provider/build \
 && so="$(find /src/oqs-provider/build -name oqsprovider.so | head -n 1)" \
 && test -n "$so" \
 && install -D -m 0644 "$so" /opt/oqs-provider/oqsprovider.so

# ---------------------------------------------------------------------------------------------
# 3. Experimental SSH: the OQS-OpenSSH client, built with its own scripts' liboqs.
#    OQS-OpenSSH publishes no release tags, so a commit is pinned. Its liboqs script clones
#    liboqs `main` unless told otherwise; the commit actually used is recorded in VERSIONS.
# ---------------------------------------------------------------------------------------------
FROM debian:${DEBIAN}-slim AS oqs-ssh
ARG OQS_OPENSSH_BRANCH=OQS-v10
ARG OQS_OPENSSH_COMMIT=4c308effc8c92dc4bcbfde10327109457626c043
ARG OQS_OPENSSH_LIBOQS=main
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential autoconf automake libtool \
      cmake ninja-build libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --single-branch --branch "${OQS_OPENSSH_BRANCH}" https://github.com/open-quantum-safe/openssh.git /src/openssh \
 && cd /src/openssh \
 && if [ -n "${OQS_OPENSSH_COMMIT}" ]; then git checkout --detach "${OQS_OPENSSH_COMMIT}"; fi \
 && git rev-parse HEAD > /oqs-openssh.commit
WORKDIR /src/openssh
RUN LIBOQS_BRANCH="${OQS_OPENSSH_LIBOQS}" ./oqs-scripts/clone_liboqs.sh \
 && git -C oqs-scripts/tmp/liboqs rev-parse HEAD > /oqs-openssh-liboqs.commit \
 && ./oqs-scripts/build_liboqs.sh \
 && test -d oqs/lib -o -d oqs/lib64
# Upstream bug open-quantum-safe/openssh#210 (present since July 2026): ssh-oqs.c includes oqs-utils.h, which includes
# sshkey.h, before defining SSHKEY_INTERNAL, so sshkey.h's internal declarations are hidden
# behind its include guard. GCC 13 only warns about the resulting implicit declaration of
# sshkey_clear_pkey; GCC 14 (Debian 13) refuses. Define it before the first include, as the
# file intends. Applied only while the file still has that layout.
RUN if grep -q '^#define SSHKEY_INTERNAL' ssh-oqs.c \
      && [ "$(grep -n '#include "oqs-utils.h"' ssh-oqs.c | cut -d: -f1)" -lt "$(grep -n '^#define SSHKEY_INTERNAL' ssh-oqs.c | cut -d: -f1)" ]; then \
      sed -i '0,/^#include "includes.h"/s//#define SSHKEY_INTERNAL\n#include "includes.h"/' ssh-oqs.c \
      && echo "patched ssh-oqs.c (SSHKEY_INTERNAL before includes)"; \
    fi
# open-quantum-safe/openssh#211, same kind of bug: kex.c defines kex_reset_keys and kexgen.c calls it, but kex.h
# has no prototype. Added only if kex.h still lacks one.
RUN if ! grep -q 'kex_reset_keys' kex.h; then \
      sed -i '/^int[[:space:]]*kex_derive_keys(/a void\tkex_reset_keys(struct kex *);' kex.h \
      && grep -q 'kex_reset_keys' kex.h \
      && echo "patched kex.h (kex_reset_keys prototype)"; \
    fi
# Only the client is built: the probe never runs sshd. The script builds liboqs as a shared
# library, so it is shipped next to ssh and found through a run path. A run path is searched
# before the system library cache, so ssh never picks up the TLS stack's liboqs by mistake.
# -Werror=implicit-function-declaration keeps the build strict on any compiler.
RUN autoreconf -i \
 && ./configure --prefix=/opt/oqs-openssh --sysconfdir=/opt/oqs-openssh/etc \
      --with-liboqs-dir=/src/openssh/oqs \
      --with-ldflags="-Wl,-rpath,/opt/oqs-openssh/lib" \
      --with-cflags="-Werror=implicit-function-declaration" \
 && make -j"$(nproc)" ssh \
 && install -D -m 0755 ssh /opt/oqs-openssh/bin/ssh \
 && install -d /opt/oqs-openssh/lib \
 && cp -a oqs/lib/liboqs.so* /opt/oqs-openssh/lib/

# ---------------------------------------------------------------------------------------------
# 4. Runtime
# ---------------------------------------------------------------------------------------------
FROM debian:${DEBIAN}-slim
ARG LIBOQS_VERSION=0.15.0
ARG OQS_PROVIDER_VERSION=0.11.0
ARG OQS_OPENSSH_BRANCH=OQS-v10
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl openssh-client \
 && rm -rf /var/lib/apt/lists/*

COPY --from=oqs-provider /opt/liboqs/lib /opt/liboqs/lib
COPY --from=oqs-provider /opt/oqs-provider /opt/oqs-provider
COPY --from=oqs-ssh /opt/oqs-openssh /opt/oqs-openssh
COPY --from=oqs-ssh /oqs-openssh.commit /opt/pqc-probe/oqs-openssh.commit
COPY --from=oqs-ssh /oqs-openssh-liboqs.commit /opt/pqc-probe/oqs-openssh-liboqs.commit
COPY --from=rust /out/ /usr/local/bin/
COPY docker/openssl-oqs.cnf /etc/pqc-probe/openssl-oqs.cnf
COPY docker/openssl-oqs /usr/local/bin/openssl-oqs
RUN echo /opt/liboqs/lib > /etc/ld.so.conf.d/liboqs.conf && ldconfig

# Fail the build if either experimental stack is not really there.
RUN set -e \
 && openssl-oqs list -providers | grep -qi oqsprovider \
 && openssl-oqs list -kem-algorithms | grep -qi frodo \
 && /opt/oqs-openssh/bin/ssh -Q kex | grep -q openquantumsafe \
 && { \
      echo "pqc-probe image"; \
      echo "liboqs (TLS): ${LIBOQS_VERSION}"; \
      echo "oqs-provider: ${OQS_PROVIDER_VERSION}"; \
      echo "OQS-OpenSSH: ${OQS_OPENSSH_BRANCH} @ $(cat /opt/pqc-probe/oqs-openssh.commit)"; \
      echo "liboqs (SSH): $(cat /opt/pqc-probe/oqs-openssh-liboqs.commit)"; \
      echo "stock openssl: $(openssl version)"; \
      echo "stock ssh: $(ssh -V 2>&1)"; \
      echo "experimental ssh: $(/opt/oqs-openssh/bin/ssh -V 2>&1)"; \
    } > /opt/pqc-probe/VERSIONS \
 && cat /opt/pqc-probe/VERSIONS

RUN useradd --system --uid 10001 --create-home --home-dir /home/pqc --shell /usr/sbin/nologin pqc

ENV PQC_PROBE_OPENSSL=/usr/bin/openssl \
    PQC_PROBE_OPENSSL_OQS=/usr/local/bin/openssl-oqs \
    PQC_PROBE_SSH=/usr/bin/ssh \
    PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh \
    PQC_WEB_BIND=0.0.0.0:8080

USER pqc
WORKDIR /home/pqc
EXPOSE 8080
# The service shuts down cleanly on SIGINT; as PID 1 it would otherwise ignore SIGTERM.
STOPSIGNAL SIGINT
CMD ["pqc-probe-web"]
