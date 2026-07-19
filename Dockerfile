FROM ghcr.io/libops/go:1.26.5@sha256:f952de0a7e29d3232292d98e2a9fe4855719d4179f0df35090b5a3c01a5167ba AS builder

SHELL ["/bin/ash", "-o", "pipefail", "-ex", "-c"]

ENV CGO_ENABLED=0 \
  GOOS=linux

ARG GIT_BRANCH=devel

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY main.go .
RUN --mount=type=cache,target=/root/.cache/go-build \
  go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${GIT_BRANCH}" \
  -tags "osusergo netgo" \
  -o /bin/vault-init \
  .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/vault-init /bin/vault-init
USER 65532:65532
ENTRYPOINT ["/bin/vault-init"]
