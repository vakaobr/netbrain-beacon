# syntax=docker/dockerfile:1.7
# ---------- builder ----------
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache go.mod / go.sum layer before sources for faster rebuilds.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w -buildid= -X main.version=$VERSION" \
      -o /out/netbrain-beacon ./cmd/netbrain-beacon

# ---------- runtime ----------
# distroless static, non-root (UID 65532). No shell, no package manager, no apk.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/netbrain-beacon /usr/local/bin/netbrain-beacon

# State directory must be writable by UID 65532 — operator mounts a volume here.
USER 65532:65532
WORKDIR /var/lib/netbrain-beacon
VOLUME ["/var/lib/netbrain-beacon"]

# Prometheus loopback port (D-8). Only reachable from inside the container by default;
# operators expose explicitly when remote scraping is required.
EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/netbrain-beacon"]
CMD ["version"]
