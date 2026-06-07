FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /bin/proxy ./cmd/proxy

# ---
FROM scratch

COPY --from=builder /bin/proxy /proxy
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Default config is bind-mounted at runtime; provide a fallback path.
VOLUME ["/config"]
ENTRYPOINT ["/proxy"]
CMD ["-config", "/config/config.yaml"]

EXPOSE 443
EXPOSE 9090
