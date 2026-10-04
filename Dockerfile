# syntax=docker/dockerfile:1
# Build context: the complete v0.3.0 application tree (including sdk/c/tpr and
# vendor). This recipe may be supplied separately from that immutable tree.
# Both index digests include native linux/amd64 and linux/arm64 images.
FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS builder

ARG APP_VERSION=0.3.0
ARG SOURCE_REVISION=aecc2fd8247aec361e5573412b7bfd6e75a83127
ARG NATIVE_JOBS=4
ENV CC=gcc CXX=g++ CGO_ENABLED=1 \
    GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor \
    TMPDIR=/tmp XDG_CACHE_HOME=/build/cache GOCACHE=/build/go-cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build python3 \
    && rm -rf /var/lib/apt/lists/* \
    && test "$(go env GOVERSION)" = go1.27.1 \
    && mkdir -p /build/cache /out
WORKDIR /src
COPY . .

# SQLite needs cgo, but this independent command must not link the client SDK.
# Run before sourcing remote.env, and explicitly clear any inherited cgo flags.
RUN CGO_CFLAGS= CGO_CPPFLAGS= CGO_CXXFLAGS= CGO_LDFLAGS= \
    go build -buildvcs=false -trimpath -o /out/oheco-broker-server ./cmd/oheco-broker-server \
    && test "$(/out/oheco-broker-server --version)" = "oheco-broker-server ${APP_VERSION}"

# All application/native dependency inputs are local; Go cannot download modules
# or switch toolchains. The SDK's probes execute on the target Linux platform.
# The release's strict C11 relay probe includes POSIX pthread declarations.
# Enable glibc's default POSIX interfaces through the Linux compiler invocation;
# application and pinned dependency sources remain the release's original bytes.
RUN printf '%s\n' '#!/bin/sh' 'exec gcc -D_DEFAULT_SOURCE "$@"' > /usr/local/bin/oheco-linux-cc \
    && chmod 0755 /usr/local/bin/oheco-linux-cc
ENV CC=/usr/local/bin/oheco-linux-cc
RUN NATIVE_JOBS="${NATIVE_JOBS}" sh sdk/c/build.sh --build-dir /build/sdk
RUN . /build/sdk/remote-sdk/remote.env \
    && go test -count=1 -timeout=180s ./... \
    && go vet ./... \
    && go build -buildvcs=false -trimpath -o /out/oheco-broker ./cmd/oheco-broker \
    && test "$(/out/oheco-broker --version)" = "oheco-broker ${APP_VERSION}"

# Linux adaptation of test-remote.sh: use the SDK-selected compiler/runtime.
# Keep the project script and application sources from the release unchanged.
RUN . /build/sdk/remote-sdk/remote.env \
    && cmake -S sdk/c/remote -B /build/sdk/remote-sdk \
        -DOB_REMOTE_BUILD_TESTS=ON -DOB_REMOTE_TEST_SOURCE_DIR=/src/tests/c \
    && cmake --build /build/sdk/remote-sdk --parallel "${NATIVE_JOBS}" \
    && gcc -std=c11 -D_GNU_SOURCE -DJUICE_STATIC -DCURL_STATICLIB -Wall -Wextra -Werror -pthread \
        -Isdk/c/remote -I"${OB_NATIVE_PREFIX}/include" -I"${OB_CURL_PREFIX}/include" \
        sdk/c/remote/ob_api.c sdk/c/remote/ob_json.c tests/c/remote_api_test.c \
        "${OB_CURL_PREFIX}/lib/libcurl.a" "${OB_NATIVE_PREFIX}/lib/libcjson.a" \
        "${OB_NATIVE_PREFIX}/lib/libssl.a" "${OB_NATIVE_PREFIX}/lib/libcrypto.a" \
        -l"${OB_CXX_RUNTIME}" -pthread -lm -ldl -o /build/remote-api-test \
    && go build -buildvcs=false -trimpath -o /build/control-fixture ./tests/control-server \
    && /build/remote-api-test \
    && /build/remote-api-test --keylog-existing \
    && /build/sdk/remote-sdk/websocket_test \
    && /build/sdk/remote-sdk/remote_peer_test \
    && python3 -B tests/cli_control.py /out/oheco-broker \
    && python3 -B tests/remote_acceptance.py --fixture /build/control-fixture \
        --native /build/sdk/remote-sdk/remote_peer_test --api-test /build/remote-api-test \
        --binary /out/oheco-broker \
    && python3 -B tests/peer_lifecycle.py --fixture /build/control-fixture --binary /out/oheco-broker

# Keep the original project, Go runtime, and vendored dependency notices. Debian
# runtime package copyright files remain in /usr/share/doc in the final stage.
RUN python3 - <<'PY'
from pathlib import Path
import shutil
root = Path('/src')
out = Path('/out/licenses')
out.mkdir()
shutil.copy2(root / 'LICENSE', out / 'LICENSE')
shutil.copy2('/usr/local/go/LICENSE', out / 'Go-LICENSE')
for tree in ('vendor', 'sdk/c/tpr'):
    for source in (root / tree).rglob('*'):
        name = source.name.upper()
        if source.is_file() and (name.startswith(('LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'PATENTS'))):
            target = out / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
shutil.copy2(root / 'sdk/c/tpr/native-dependencies.json', out / 'native-dependencies.json')
shutil.copytree(root / 'sdk/c/tpr/manifests', out / 'native-manifests')
shutil.copy2(root / 'vendor/modules.txt', out / 'go-vendor-modules.txt')
PY

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
ARG APP_VERSION=0.3.0
ARG SOURCE_REVISION=aecc2fd8247aec361e5573412b7bfd6e75a83127
LABEL org.opencontainers.image.title="oheco-broker" \
      org.opencontainers.image.description="Independent SQLite/TLS/STUN-TURN server and native C SDK broker CLI" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.source="https://github.com/oheco/oheco-broker" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update \
    && apt-get install -y --no-install-recommends libc6 libgcc-s1 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 oheco-broker \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/oheco-broker \
        --shell /usr/sbin/nologin oheco-broker \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/oheco-broker \
        /var/lib/oheco-broker/db /var/lib/oheco-broker/config /var/lib/oheco-broker/acme \
    && ln -sf /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem
COPY --from=builder --chmod=0755 /out/oheco-broker /out/oheco-broker-server /usr/local/bin/
COPY --from=builder /out/licenses/ /usr/share/licenses/oheco-broker/
# Check the dynamic closure in the actual slim root, not in the toolchain image.
RUN ldd /usr/local/bin/oheco-broker > /tmp/cli-ldd \
    && ldd /usr/local/bin/oheco-broker-server > /tmp/server-ldd \
    && ! grep -q 'not found' /tmp/cli-ldd /tmp/server-ldd \
    && grep -q 'libstdc++\.so' /tmp/cli-ldd \
    && ! grep -q 'libstdc++\|libob_remote\|libcurl\|libxquic' /tmp/server-ldd \
    && rm /tmp/cli-ldd /tmp/server-ldd
ENV HOME=/var/lib/oheco-broker \
    XDG_CONFIG_HOME=/var/lib/oheco-broker/config \
    XDG_CACHE_HOME=/var/lib/oheco-broker/acme \
    TMPDIR=/tmp SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /var/lib/oheco-broker
USER 10001:10001
VOLUME ["/var/lib/oheco-broker"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/oheco-broker-server"]
CMD ["--db", "/var/lib/oheco-broker/db/control.sqlite"]
