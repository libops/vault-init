FROM ghcr.io/libops/go:1.26.5@sha256:ea764e85e42a243217c621891123b3fda9374674c29d59785414fc6b15815b3d AS builder

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
