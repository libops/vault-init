FROM golang:1.25.4@sha256:e68f6a00e88586577fafa4d9cefad1349c2be70d21244321321c407474ff9bf2 AS builder

RUN apt-get -qq update && \
    apt-get -yqq install curl -y

ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

WORKDIR /src

COPY . .
RUN go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags '-static'" \
  -tags 'osusergo netgo static_build' \
  -o /bin/vault-init \
  .

RUN strip /bin/vault-init

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/vault-init /bin/vault-init
CMD ["/bin/vault-init"]
