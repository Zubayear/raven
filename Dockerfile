# docker build -t raven .                # the server image
# docker build --target smoke .          # runs the smoke test against it
#
# debian:trixie-slim, pinned by digest; update with
# `docker buildx imagetools inspect debian:trixie-slim`.
ARG BASE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE} AS build
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
# Zig 0.17.1, checked against the SHA-256 sums published on ziglang.org.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; sum=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;; \
      arm64) arch=aarch64; sum=a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/0.17.1/zig-$arch-linux-0.17.1.tar.xz"; \
    echo "$sum  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz
WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src src
RUN /opt/zig/zig build -Doptimize=ReleaseSafe

FROM ${BASE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --no-create-home --home-dir /data raven \
 && install -d -o raven -g raven -m 0700 /data
COPY --from=build /src/zig-out/bin/raven /usr/local/bin/raven
USER raven
# Unprivileged ports, so no capabilities are needed; publish them as the
# standard ones (docker run -p 25:2525 -p 587:2587 -p 143:2143 ...).
# Mount a certificate and set RAVEN_TLS_CERT / RAVEN_TLS_KEY for STARTTLS,
# plus RAVEN_SMTPS_PORT=2465 and RAVEN_IMAPS_PORT=2993 for implicit TLS.
ENV RAVEN_LISTEN_ADDRESS=0.0.0.0 \
    RAVEN_DATA_DIR=/data \
    RAVEN_LISTEN_PORT=2525 \
    RAVEN_SUBMISSION_PORT=2587 \
    RAVEN_IMAP_PORT=2143
EXPOSE 2525 2587 2143 2465 2993
VOLUME /data
ENTRYPOINT ["raven"]

FROM runtime AS smoke
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-dkim openssl \
 && rm -rf /var/lib/apt/lists/*
USER raven
WORKDIR /tmp
COPY scripts/smoke.py /tmp/smoke.py
# The smoke test picks its own ports; the image's submission port would clash.
RUN env -u RAVEN_SUBMISSION_PORT CI=1 RAVEN_BIN=/usr/local/bin/raven python3 /tmp/smoke.py
